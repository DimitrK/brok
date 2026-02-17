import {badRequest} from './errors'

type DerNode = {
  tag: number
  value: Uint8Array
}

type ReadNodeResult = {
  node: DerNode
  nextOffset: number
}

const tagSequence = 0x30
const tagSet = 0x31
const tagObjectIdentifier = 0x06
const tagOctetString = 0x04
const tagContextSpecificZero = 0xa0
const tagContextSpecificUri = 0x86

const EXTENSION_REQUEST_OID = '1.2.840.113549.1.9.14'
const SAN_OID = '2.5.29.17'
const EKU_OID = '2.5.29.37'
const EKU_CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2'

const decodeLength = ({
  bytes,
  offset
}: {
  bytes: Uint8Array
  offset: number
}): {length: number; nextOffset: number} => {
  if (offset >= bytes.length) {
    throw badRequest('csr_invalid', 'CSR ASN.1 length is truncated')
  }

  // eslint-disable-next-line security/detect-object-injection -- Offset is bounds-checked and used for DER byte parsing.
  const firstByte = bytes[offset]
  if (firstByte < 0x80) {
    return {
      length: firstByte,
      nextOffset: offset + 1
    }
  }

  const byteCount = firstByte & 0x7f
  if (byteCount === 0 || byteCount > 4) {
    throw badRequest('csr_invalid', 'CSR ASN.1 length encoding is invalid')
  }

  if (offset + 1 + byteCount > bytes.length) {
    throw badRequest('csr_invalid', 'CSR ASN.1 length value is truncated')
  }

  let length = 0
  for (let index = 0; index < byteCount; index += 1) {
    length = (length << 8) | bytes[offset + 1 + index]
  }

  return {
    length,
    nextOffset: offset + 1 + byteCount
  }
}

const readNode = ({bytes, offset}: {bytes: Uint8Array; offset: number}): ReadNodeResult => {
  if (offset >= bytes.length) {
    throw badRequest('csr_invalid', 'CSR ASN.1 node is truncated')
  }

  // eslint-disable-next-line security/detect-object-injection -- Offset is bounds-checked and used for DER byte parsing.
  const tag = bytes[offset]
  const lengthResult = decodeLength({bytes, offset: offset + 1})
  const valueStart = lengthResult.nextOffset
  const valueEnd = valueStart + lengthResult.length

  if (valueEnd > bytes.length) {
    throw badRequest('csr_invalid', 'CSR ASN.1 node payload is truncated')
  }

  return {
    node: {
      tag,
      value: bytes.slice(valueStart, valueEnd)
    },
    nextOffset: valueEnd
  }
}

const parseChildren = ({node, expectedTag}: {node: DerNode; expectedTag: number}): DerNode[] => {
  if (node.tag !== expectedTag) {
    throw badRequest('csr_invalid', `CSR ASN.1 expected tag ${expectedTag.toString(16)}`)
  }

  const children: DerNode[] = []
  let offset = 0
  while (offset < node.value.length) {
    const child = readNode({bytes: node.value, offset})
    children.push(child.node)
    offset = child.nextOffset
  }

  if (offset !== node.value.length) {
    throw badRequest('csr_invalid', 'CSR ASN.1 child parsing did not consume full payload')
  }

  return children
}

const decodeOid = (node: DerNode) => {
  if (node.tag !== tagObjectIdentifier || node.value.length === 0) {
    throw badRequest('csr_invalid', 'CSR ASN.1 object identifier is invalid')
  }

  const first = node.value[0]
  const parts = [Math.floor(first / 40), first % 40]
  let current = 0

  for (let index = 1; index < node.value.length; index += 1) {
    // eslint-disable-next-line security/detect-object-injection -- Index is range-bound by node.value.length in DER parser loop.
    const byte = node.value[index]
    current = (current << 7) | (byte & 0x7f)
    if ((byte & 0x80) === 0) {
      parts.push(current)
      current = 0
    }
  }

  if (current !== 0) {
    throw badRequest('csr_invalid', 'CSR ASN.1 object identifier terminator is missing')
  }

  return parts.join('.')
}

const parseDerFromBytes = ({bytes}: {bytes: Uint8Array}) => {
  const parsed = readNode({bytes, offset: 0})
  if (parsed.nextOffset !== bytes.length) {
    throw badRequest('csr_invalid', 'CSR ASN.1 contains trailing bytes')
  }

  return parsed.node
}

const parsePemToDer = (pem: string) => {
  const normalized = pem.trim()
  if (!normalized.startsWith('-----BEGIN CERTIFICATE REQUEST-----')) {
    throw badRequest('csr_invalid', 'CSR PEM header is missing')
  }

  if (!normalized.includes('-----END CERTIFICATE REQUEST-----')) {
    throw badRequest('csr_invalid', 'CSR PEM footer is missing')
  }

  const base64 = normalized
    .replace('-----BEGIN CERTIFICATE REQUEST-----', '')
    .replace('-----END CERTIFICATE REQUEST-----', '')
    .replace(/\s+/gu, '')

  if (base64.length === 0) {
    throw badRequest('csr_invalid', 'CSR PEM body is empty')
  }

  return Buffer.from(base64, 'base64')
}

type CsrMetadata = {
  sanUris: string[]
  extKeyUsageOids: string[]
}

const parseSanUris = (extensionNode: DerNode): string[] => {
  const root = parseDerFromBytes({bytes: extensionNode.value})
  const generalNames = parseChildren({node: root, expectedTag: tagSequence})
  return generalNames
    .filter(entry => entry.tag === tagContextSpecificUri)
    .map(entry => Buffer.from(entry.value).toString('ascii'))
    .filter(value => value.length > 0)
}

const parseEkuOids = (extensionNode: DerNode): string[] => {
  const root = parseDerFromBytes({bytes: extensionNode.value})
  const usages = parseChildren({node: root, expectedTag: tagSequence})
  return usages.map(entry => decodeOid(entry))
}

const parseExtensions = (attributesNode: DerNode): CsrMetadata => {
  const attributes = parseChildren({node: attributesNode, expectedTag: tagContextSpecificZero})
  const extensionRequestAttribute = attributes.find(attribute => {
    const attributeFields = parseChildren({node: attribute, expectedTag: tagSequence})
    if (attributeFields.length < 2) {
      return false
    }

    return decodeOid(attributeFields[0]) === EXTENSION_REQUEST_OID
  })

  if (!extensionRequestAttribute) {
    return {sanUris: [], extKeyUsageOids: []}
  }

  const attributeFields = parseChildren({node: extensionRequestAttribute, expectedTag: tagSequence})
  if (attributeFields.length < 2) {
    throw badRequest('csr_invalid', 'CSR extension request attribute is malformed')
  }

  const values = parseChildren({node: attributeFields[1], expectedTag: tagSet})
  if (values.length === 0) {
    throw badRequest('csr_invalid', 'CSR extension request attribute has no values')
  }

  const extensions = parseChildren({node: values[0], expectedTag: tagSequence})
  const sanUris: string[] = []
  const extKeyUsageOids: string[] = []

  for (const extension of extensions) {
    const fields = parseChildren({node: extension, expectedTag: tagSequence})
    if (fields.length < 2) {
      throw badRequest('csr_invalid', 'CSR extension entry is malformed')
    }

    const oid = decodeOid(fields[0])
    const valueNode = fields.find(field => field.tag === tagOctetString)
    if (!valueNode) {
      throw badRequest('csr_invalid', 'CSR extension value is missing')
    }

    if (oid === SAN_OID) {
      sanUris.push(...parseSanUris(valueNode))
    }

    if (oid === EKU_OID) {
      extKeyUsageOids.push(...parseEkuOids(valueNode))
    }
  }

  return {sanUris, extKeyUsageOids}
}

export const extractCsrMetadata = ({csrPem}: {csrPem: string}): CsrMetadata => {
  const der = parsePemToDer(csrPem)
  const root = parseDerFromBytes({bytes: der})
  const csrFields = parseChildren({node: root, expectedTag: tagSequence})

  if (csrFields.length < 3) {
    throw badRequest('csr_invalid', 'CSR top-level sequence is malformed')
  }

  const certificationRequestInfo = csrFields[0]
  const criFields = parseChildren({node: certificationRequestInfo, expectedTag: tagSequence})
  const attributesNode = criFields.find(field => field.tag === tagContextSpecificZero)

  if (!attributesNode) {
    throw badRequest('csr_invalid', 'CSR does not include extension attributes')
  }

  return parseExtensions(attributesNode)
}

export const validateCsrForWorkload = ({
  csrPem,
  expectedSanUri,
  requireClientAuthEku
}: {
  csrPem: string
  expectedSanUri: string
  requireClientAuthEku: boolean
}) => {
  const metadata = extractCsrMetadata({csrPem})
  if (!metadata.sanUris.includes(expectedSanUri)) {
    throw badRequest('csr_san_mismatch', 'CSR SAN URIs do not include the expected workload SAN URI')
  }

  if (requireClientAuthEku && !metadata.extKeyUsageOids.includes(EKU_CLIENT_AUTH_OID)) {
    throw badRequest('csr_eku_missing', 'CSR EKU does not include clientAuth usage')
  }
}

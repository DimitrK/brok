import {describe, expect, it} from 'vitest'

import {extractCsrMetadata, validateCsrForWorkload} from '../csr'
import {isAppError} from '../errors'

const encodeLength = (length: number) => {
  if (length < 0x80) {
    return Buffer.from([length])
  }

  const bytes: number[] = []
  let remaining = length
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff)
    remaining >>= 8
  }

  return Buffer.from([0x80 | bytes.length, ...bytes])
}

const encodeNode = (tag: number, payload: Buffer) =>
  Buffer.concat([Buffer.from([tag]), encodeLength(payload.length), payload])

const encodeOid = (oid: string) => {
  const parts = oid.split('.').map(part => Number.parseInt(part, 10))
  if (parts.length < 2) {
    throw new Error('invalid OID')
  }

  const first = parts[0] * 40 + parts[1]
  const tail = parts.slice(2).flatMap(part => {
    const encoded: number[] = [part & 0x7f]
    let value = part >> 7
    while (value > 0) {
      encoded.unshift((value & 0x7f) | 0x80)
      value >>= 7
    }
    return encoded
  })

  return Buffer.from([first, ...tail])
}

const toPem = (der: Buffer) => {
  const base64 = der.toString('base64')
  const wrapped = base64.match(/.{1,64}/gu)?.join('\n') ?? base64
  return `-----BEGIN CERTIFICATE REQUEST-----\n${wrapped}\n-----END CERTIFICATE REQUEST-----`
}

const buildCsrPem = ({sanUri, includeClientAuthEku}: {sanUri: string; includeClientAuthEku: boolean}) => {
  const extReqOid = encodeNode(0x06, encodeOid('1.2.840.113549.1.9.14'))
  const sanOid = encodeNode(0x06, encodeOid('2.5.29.17'))
  const ekuOid = encodeNode(0x06, encodeOid('2.5.29.37'))

  const sanValue = encodeNode(0x30, encodeNode(0x86, Buffer.from(sanUri, 'ascii')))
  const sanExtension = encodeNode(0x30, Buffer.concat([sanOid, encodeNode(0x04, sanValue)]))

  const ekuUsageOid = encodeNode(
    0x06,
    encodeOid(includeClientAuthEku ? '1.3.6.1.5.5.7.3.2' : '1.3.6.1.5.5.7.3.1')
  )
  const ekuValue = encodeNode(0x30, ekuUsageOid)
  const ekuExtension = encodeNode(0x30, Buffer.concat([ekuOid, encodeNode(0x04, ekuValue)]))

  const extensions = encodeNode(0x30, Buffer.concat([sanExtension, ekuExtension]))
  const attribute = encodeNode(0x30, Buffer.concat([extReqOid, encodeNode(0x31, extensions)]))
  const attributes = encodeNode(0xa0, attribute)

  const cri = encodeNode(
    0x30,
    Buffer.concat([
      encodeNode(0x02, Buffer.from([0x00])),
      encodeNode(0x30, Buffer.alloc(0)),
      encodeNode(0x30, Buffer.alloc(0)),
      attributes
    ])
  )

  const csr = encodeNode(
    0x30,
    Buffer.concat([cri, encodeNode(0x30, Buffer.alloc(0)), encodeNode(0x03, Buffer.from([0x00]))])
  )

  return toPem(csr)
}

describe('csr parsing', () => {
  it('extracts SAN URI and EKU OIDs from a syntactically valid CSR', () => {
    const expectedSan = 'spiffe://broker/tenants/t_1/workloads/w_1'
    const csrPem = buildCsrPem({sanUri: expectedSan, includeClientAuthEku: true})

    const metadata = extractCsrMetadata({csrPem})
    expect(metadata.sanUris).toContain(expectedSan)
    expect(metadata.extKeyUsageOids).toContain('1.3.6.1.5.5.7.3.2')
  })

  it('validates SAN URI and clientAuth EKU constraints', () => {
    const expectedSan = 'spiffe://broker/tenants/t_1/workloads/w_1'
    const validCsr = buildCsrPem({sanUri: expectedSan, includeClientAuthEku: true})

    expect(() =>
      validateCsrForWorkload({
        csrPem: validCsr,
        expectedSanUri: expectedSan,
        requireClientAuthEku: true
      })
    ).not.toThrow()

    const wrongSanCsr = buildCsrPem({
      sanUri: 'spiffe://broker/tenants/t_1/workloads/other',
      includeClientAuthEku: true
    })
    try {
      validateCsrForWorkload({
        csrPem: wrongSanCsr,
        expectedSanUri: expectedSan,
        requireClientAuthEku: true
      })
      throw new Error('expected SAN mismatch failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('csr_san_mismatch')
    }

    const missingEkuCsr = buildCsrPem({sanUri: expectedSan, includeClientAuthEku: false})
    try {
      validateCsrForWorkload({
        csrPem: missingEkuCsr,
        expectedSanUri: expectedSan,
        requireClientAuthEku: true
      })
      throw new Error('expected clientAuth EKU failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('csr_eku_missing')
    }
  })

  it('fails closed for malformed CSR input', () => {
    try {
      extractCsrMetadata({
        csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----'
      })
      throw new Error('expected malformed csr failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code.startsWith('csr_')).toBe(true)
    }
  })
})

import {mkdtempSync, promises as fs, rmSync, writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {webcrypto} from 'node:crypto'
import {afterEach, describe, expect, it, vi} from 'vitest'
import * as x509 from '@peculiar/x509'

import {CertificateIssuer} from '../certificateIssuer'
import {isAppError} from '../errors'

const mockCaPem = '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'

const createLocalArtifacts = async () => {
  const caKeys = await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  )

  const caCertificate = await x509.X509CertificateGenerator.createSelfSigned({
    name: 'CN=Local Test CA',
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)
    ]
  })

  const workloadKeys = await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  )

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: 'CN=workload',
    keys: workloadKeys,
    signingAlgorithm: {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    }
  })

  const caPrivateKeyDer = await webcrypto.subtle.exportKey('pkcs8', caKeys.privateKey)

  return {
    caCertPem: x509.PemConverter.encode(caCertificate.rawData, 'CERTIFICATE'),
    caKeyPem: x509.PemConverter.encode(caPrivateKeyDer, 'PRIVATE KEY'),
    csrPem: x509.PemConverter.encode(csr.rawData, 'CERTIFICATE REQUEST'),
    caKeys
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('certificate issuer', () => {
  it('issues mock certificates', async () => {
    const issuer = new CertificateIssuer({
      mode: 'mock',
      mtlsCaPem: mockCaPem
    })

    const issued = await issuer.issue({
      csrPem: 'csr-data',
      workloadId: 'w_1',
      sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
      ttlSeconds: 600
    })

    expect(issued.clientCertPem).toContain('BEGIN CERTIFICATE')
    expect(issued.caChainPem).toBe(mockCaPem)
    expect(issuer.mtlsCaPem).toBe(mockCaPem)
  })

  it('issues vault certificates when configured', async () => {
    const fetchSpy = vi.fn(() =>
      Promise.resolve({
        ok: true,
        headers: {
          get: () => 'application/json'
        },
        json: () =>
          Promise.resolve({
            data: {
              certificate: 'cert-pem',
              ca_chain: ['ca-1', 'ca-2']
            }
          })
      })
    )
    vi.stubGlobal('fetch', fetchSpy)

    const issuer = new CertificateIssuer({
      mode: 'vault',
      mtlsCaPem: mockCaPem,
      vaultAddr: 'https://vault.example',
      vaultToken: 'vault-token',
      vaultPkiMount: 'pki',
      vaultPkiRole: 'broker-workload',
      vaultRequestTimeoutMs: 2_000
    })

    const issued = await issuer.issue({
      csrPem: 'csr-data',
      workloadId: 'w_1',
      sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
      ttlSeconds: 600
    })

    expect(issued.clientCertPem).toBe('cert-pem')
    expect(issued.caChainPem).toBe('ca-1\nca-2')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const requestOptions = (fetchSpy.mock.calls[0] as unknown[])[1] as {
      method?: string
      headers?: Record<string, string>
      redirect?: string
      signal?: AbortSignal
    }
    expect(requestOptions.method).toBe('POST')
    expect(requestOptions.redirect).toBe('error')
    expect(requestOptions.headers?.['x-vault-token']).toBe('vault-token')
    expect(requestOptions.signal).toBeInstanceOf(AbortSignal)
  })

  it('fails closed when vault returns invalid response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve({
        ok: true,
        headers: {
          get: () => 'application/json'
        },
        json: () => Promise.resolve({data: {certificate: null}})
      }))
    )

    const issuer = new CertificateIssuer({
      mode: 'vault',
      mtlsCaPem: mockCaPem,
      vaultAddr: 'https://vault.example',
      vaultToken: 'vault-token',
      vaultPkiMount: 'pki',
      vaultPkiRole: 'broker-workload',
      vaultRequestTimeoutMs: 2_000
    })

    try {
      await issuer.issue({
        csrPem: 'csr-data',
        workloadId: 'w_1',
        sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
        ttlSeconds: 600
      })
      throw new Error('expected vault failure')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('vault_response_invalid')
    }
  })

  it('fails closed when vault request times out', async () => {
    const timeoutError = new Error('timeout')
    timeoutError.name = 'TimeoutError'
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(timeoutError)))

    const issuer = new CertificateIssuer({
      mode: 'vault',
      mtlsCaPem: mockCaPem,
      vaultAddr: 'https://vault.example',
      vaultToken: 'vault-token',
      vaultPkiMount: 'pki',
      vaultPkiRole: 'broker-workload',
      vaultRequestTimeoutMs: 1
    })

    await expect(
      issuer.issue({
        csrPem: 'csr-data',
        workloadId: 'w_1',
        sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
        ttlSeconds: 600
      })
    ).rejects.toMatchObject({
      code: 'vault_unreachable'
    })
  })

  it('fails closed when vault responds with non-json content-type', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          headers: {
            get: () => 'text/plain'
          },
          json: () =>
            Promise.resolve({
              data: {
                certificate: 'cert-pem',
                ca_chain: ['ca-1']
              }
            })
        })
      )
    )

    const issuer = new CertificateIssuer({
      mode: 'vault',
      mtlsCaPem: mockCaPem,
      vaultAddr: 'https://vault.example',
      vaultToken: 'vault-token',
      vaultPkiMount: 'pki',
      vaultPkiRole: 'broker-workload',
      vaultRequestTimeoutMs: 2_000
    })

    await expect(
      issuer.issue({
        csrPem: 'csr-data',
        workloadId: 'w_1',
        sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
        ttlSeconds: 600
      })
    ).rejects.toMatchObject({
      code: 'vault_response_invalid'
    })
  })

  it('fails closed in local mode when CA files cannot be loaded', async () => {
    vi.spyOn(fs, 'readFile').mockRejectedValue(new Error('ENOENT'))

    const issuer = new CertificateIssuer({
      mode: 'local',
      mtlsCaPem: mockCaPem,
      caCertPath: '/missing/ca.crt',
      caKeyPath: '/missing/ca.key'
    })

    await expect(
      issuer.issue({
        csrPem: 'csr-data',
        workloadId: 'w_1',
        sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
        ttlSeconds: 600
      })
    ).rejects.toMatchObject({
      code: 'local_ca_unavailable'
    })
  })

  it('issues valid local certificates and caches local CA file reads', async () => {
    const artifacts = await createLocalArtifacts()
    const tempDir = mkdtempSync(join(tmpdir(), 'broker-admin-local-ca-'))
    const caCertPath = join(tempDir, 'ca.crt')
    const caKeyPath = join(tempDir, 'ca.key')
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(caCertPath, artifacts.caCertPem, 'utf8')
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(caKeyPath, artifacts.caKeyPem, 'utf8')

    const readFileSpy = vi.spyOn(fs, 'readFile')
    const issuer = new CertificateIssuer({
      mode: 'local',
      mtlsCaPem: artifacts.caCertPem,
      caCertPath,
      caKeyPath
    })

    try {
      const firstIssued = await issuer.issue({
        csrPem: artifacts.csrPem,
        workloadId: 'w_1',
        sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
        ttlSeconds: 600
      })
      const secondIssued = await issuer.issue({
        csrPem: artifacts.csrPem,
        workloadId: 'w_2',
        sanUri: 'spiffe://broker/tenants/t/workloads/w_2',
        ttlSeconds: 600
      })

      expect(firstIssued.clientCertPem).toContain('BEGIN CERTIFICATE')
      expect(secondIssued.clientCertPem).toContain('BEGIN CERTIFICATE')
      expect(firstIssued.caChainPem).toBe(artifacts.caCertPem)
      expect(secondIssued.caChainPem).toBe(artifacts.caCertPem)
      expect(readFileSpy).toHaveBeenCalledTimes(2)
    } finally {
      rmSync(tempDir, {recursive: true, force: true})
    }
  })

  it('fails closed when local CA certificate and private key do not match', async () => {
    const artifacts = await createLocalArtifacts()
    const mismatchKeys = await webcrypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    )
    const mismatchKeyDer = await webcrypto.subtle.exportKey('pkcs8', mismatchKeys.privateKey)
    const mismatchKeyPem = x509.PemConverter.encode(mismatchKeyDer, 'PRIVATE KEY')

    const tempDir = mkdtempSync(join(tmpdir(), 'broker-admin-local-ca-mismatch-'))
    const caCertPath = join(tempDir, 'ca.crt')
    const caKeyPath = join(tempDir, 'ca.key')
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(caCertPath, artifacts.caCertPem, 'utf8')
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(caKeyPath, mismatchKeyPem, 'utf8')

    const issuer = new CertificateIssuer({
      mode: 'local',
      mtlsCaPem: artifacts.caCertPem,
      caCertPath,
      caKeyPath
    })

    try {
      await expect(
        issuer.issue({
          csrPem: artifacts.csrPem,
          workloadId: 'w_1',
          sanUri: 'spiffe://broker/tenants/t/workloads/w_1',
          ttlSeconds: 600
        })
      ).rejects.toMatchObject({
        code: 'local_ca_invalid'
      })
    } finally {
      rmSync(tempDir, {recursive: true, force: true})
    }
  })
})

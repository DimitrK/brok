import {describe, expect, it} from 'vitest'

import {
  computeManifestKeysWeakEtagWithCryptoPackage,
  computeWeakEtag,
  createOpaqueToken,
  decryptSecretMaterialWithCryptoPackage,
  encryptSecretMaterialWithCryptoPackage,
  generateId,
  hashToken
} from '../crypto'
import {isAppError} from '../errors'

describe('crypto utilities', () => {
  it('generates stable hash and opaque token values', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'))
    expect(hashToken('abc')).not.toBe(hashToken('abcd'))

    const token = createOpaqueToken(24)
    expect(token.length).toBeGreaterThan(24)
    expect(/^[A-Za-z0-9_-]+$/u.test(token)).toBe(true)

    const generatedId = generateId('x_')
    expect(generatedId.startsWith('x_')).toBe(true)
    expect(generatedId.length).toBeGreaterThan(10)
  })

  it('encrypts and decrypts secret payloads', async () => {
    const key = Buffer.alloc(32, 7)
    const envelope = await encryptSecretMaterialWithCryptoPackage({
      secretMaterial: {
        type: 'api_key',
        value: 'secret-value'
      },
      key,
      keyId: 'k1',
      aadContext: {
        tenant_id: 't1',
        integration_id: 'i1'
      }
    })

    const decrypted = await decryptSecretMaterialWithCryptoPackage({
      envelope,
      secretType: 'api_key',
      key,
      keyId: 'k1',
      aadContext: {
        tenant_id: 't1',
        integration_id: 'i1'
      }
    })
    expect(decrypted).toBe('secret-value')
    expect(envelope.ciphertext_b64).not.toContain('secret-value')
  })

  it('fails closed when decryption uses the wrong key', async () => {
    const envelope = await encryptSecretMaterialWithCryptoPackage({
      secretMaterial: {
        type: 'api_key',
        value: 'secret-value'
      },
      key: Buffer.alloc(32, 8),
      keyId: 'k1',
      aadContext: {
        tenant_id: 't1',
        integration_id: 'i1'
      }
    })

    try {
      await decryptSecretMaterialWithCryptoPackage({
        envelope,
        secretType: 'api_key',
        key: Buffer.alloc(32, 9),
        keyId: 'k1',
        aadContext: {
          tenant_id: 't1',
          integration_id: 'i1'
        }
      })
      throw new Error('expected decryption to fail')
    } catch (error) {
      expect(isAppError(error)).toBe(true)
      expect((error as {code: string}).code).toBe('secret_decrypt_failed')
    }
  })

  it('computes weak etags', () => {
    const etagA = computeWeakEtag({a: 1})
    const etagB = computeWeakEtag({a: 1})
    const etagC = computeWeakEtag({a: 2})

    expect(etagA).toBe(etagB)
    expect(etagA).not.toBe(etagC)
    expect(etagA.startsWith('W/"')).toBe(true)
  })

  it('computes manifest etags with crypto package bridge', () => {
    const etag = computeManifestKeysWeakEtagWithCryptoPackage({
      manifestKeys: {
        keys: []
      }
    })
    expect(typeof etag).toBe('string')
    expect(etag.length).toBeGreaterThan(0)
  })
})

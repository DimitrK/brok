import {
  CreateSecretEnvelopeVersionInputSchema,
  CreateManifestSigningKeyRecordInputSchema,
  ManifestSigningKeyRecordSchema,
  CryptoVerificationDefaultsSchema,
  GetCryptoVerificationDefaultsByTenantInputSchema,
  ManifestVerificationKeysetWithEtagSchema,
  GetSecretEnvelopeInputSchema,
  PersistManifestKeysetMetadataInputSchema,
  SecretEnvelopeVersionSchema,
  SetActiveSecretEnvelopeVersionInputSchema,
  RetireManifestSigningKeyInputSchema,
  RevokeManifestSigningKeyInputSchema,
  SetActiveManifestSigningKeyInputSchema,
  TransitionManifestSigningKeyStatusInputSchema,
  UpsertCryptoVerificationDefaultsInputSchema,
  type CreateSecretEnvelopeVersionInput,
  type CreateManifestSigningKeyRecordInput,
  type CryptoVerificationDefaults,
  type GetSecretEnvelopeInput,
  type GetCryptoVerificationDefaultsByTenantInput,
  type ManifestSigningKeyRecord,
  type ManifestVerificationKeysetWithEtag,
  type PersistManifestKeysetMetadataInput,
  type SecretEnvelopeVersion,
  type SetActiveSecretEnvelopeVersionInput,
  type RetireManifestSigningKeyInput,
  type RevokeManifestSigningKeyInput,
  type SetActiveManifestSigningKeyInput,
  type TransitionManifestSigningKeyStatusInput,
  type UpsertCryptoVerificationDefaultsInput
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient, RepositoryOperationContext} from '../types.js'
import {ensureEnvelopeBounds, resolveRepositoryDbClient} from '../utils.js'

const toSecretEnvelopeVersion = (record: {
  secretRef: string
  version: number
  createdAt: Date
  keyId: string
  contentEncryptionAlg: string
  keyEncryptionAlg: string
  wrappedDataKeyB64: string
  ivB64: string
  ciphertextB64: string
  authTagB64: string
  aadB64: string | null
  secret: {
    tenantId: string
    integrationId: string
    type: 'api_key' | 'oauth_refresh_token'
  }
}): SecretEnvelopeVersion =>
  SecretEnvelopeVersionSchema.parse({
    secret_ref: record.secretRef,
    tenant_id: record.secret.tenantId,
    integration_id: record.secret.integrationId,
    secret_type: record.secret.type,
    version: record.version,
    envelope: {
      key_id: record.keyId,
      content_encryption_alg: record.contentEncryptionAlg,
      key_encryption_alg: record.keyEncryptionAlg,
      wrapped_data_key_b64: record.wrappedDataKeyB64,
      iv_b64: record.ivB64,
      ciphertext_b64: record.ciphertextB64,
      auth_tag_b64: record.authTagB64,
      ...(record.aadB64 ? {aad_b64: record.aadB64} : {})
    },
    created_at: record.createdAt.toISOString()
  })

const withTransaction = async <T>(db: DatabaseClient, operation: (transactionDb: DatabaseClient) => Promise<T>) => {
  if (typeof db.$transaction !== 'function') {
    throw new DbRepositoryError(
      'dependency_missing',
      'Database client must provide transactional execution for secret version writes'
    )
  }

  return db.$transaction(transactionDb => operation(transactionDb))
}

const MANIFEST_KEYSET_NAME = 'manifest_signing'

const toManifestSigningKeyRecord = (record: {
  kid: string
  alg: 'EdDSA' | 'ES256'
  publicJwk: unknown
  privateKeyRef: string
  status: 'active' | 'retired' | 'revoked'
  createdAt: Date
  activatedAt: Date | null
  retiredAt: Date | null
  revokedAt: Date | null
}): ManifestSigningKeyRecord =>
  ManifestSigningKeyRecordSchema.parse({
    kid: record.kid,
    alg: record.alg,
    public_jwk: record.publicJwk,
    private_key_ref: record.privateKeyRef,
    status: record.status,
    created_at: record.createdAt.toISOString(),
    ...(record.activatedAt ? {activated_at: record.activatedAt.toISOString()} : {}),
    ...(record.retiredAt ? {retired_at: record.retiredAt.toISOString()} : {}),
    ...(record.revokedAt ? {revoked_at: record.revokedAt.toISOString()} : {})
  })

const toCryptoVerificationDefaults = (record: {
  tenantId: string
  requireTemporalValidity: boolean
  maxClockSkewSeconds: number
}): CryptoVerificationDefaults =>
  CryptoVerificationDefaultsSchema.parse({
    tenant_id: record.tenantId,
    require_temporal_validity: record.requireTemporalValidity,
    max_clock_skew_seconds: record.maxClockSkewSeconds
  })

export class SecretRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async createSecretEnvelopeVersion(
    rawInput: CreateSecretEnvelopeVersionInput
  ): Promise<SecretEnvelopeVersion> {
    const input = CreateSecretEnvelopeVersionInputSchema.parse(rawInput)
    ensureEnvelopeBounds({
      wrapped_data_key_b64: input.envelope.wrapped_data_key_b64,
      aad_b64: input.envelope.aad_b64,
      ciphertext_b64: input.envelope.ciphertext_b64
    })

    try {
      return withTransaction(this.db, async transactionDb => {
        const existingSecret = await transactionDb.secret.findUnique({
          where: {
            secretRef: input.secret_ref
          }
        })

        if (
          existingSecret &&
          (existingSecret.tenantId !== input.tenant_id ||
            existingSecret.integrationId !== input.integration_id ||
            existingSecret.type !== input.secret_type)
        ) {
          throw new DbRepositoryError('conflict', 'Secret reference ownership mismatch')
        }

        const latestVersion = await transactionDb.secretVersion.findFirst({
          where: {
            secretRef: input.secret_ref
          },
          orderBy: {
            version: 'desc'
          },
          select: {
            version: true
          }
        })

        const nextVersion = (latestVersion?.version ?? 0) + 1

        if (!existingSecret) {
          await transactionDb.secret.create({
            data: {
              secretRef: input.secret_ref,
              tenantId: input.tenant_id,
              integrationId: input.integration_id,
              type: input.secret_type,
              activeVersion: nextVersion
            }
          })
        }

        const createdVersion = await transactionDb.secretVersion.create({
          data: {
            secretRef: input.secret_ref,
            version: nextVersion,
            keyId: input.envelope.key_id,
            contentEncryptionAlg: input.envelope.content_encryption_alg,
            keyEncryptionAlg: input.envelope.key_encryption_alg,
            wrappedDataKeyB64: input.envelope.wrapped_data_key_b64,
            ivB64: input.envelope.iv_b64,
            ciphertextB64: input.envelope.ciphertext_b64,
            authTagB64: input.envelope.auth_tag_b64,
            aadB64: input.envelope.aad_b64,
            createdAt: input.created_at ? new Date(input.created_at) : new Date()
          },
          include: {
            secret: {
              select: {
                tenantId: true,
                integrationId: true,
                type: true
              }
            }
          }
        })

        await transactionDb.secret.update({
          where: {
            secretRef: input.secret_ref
          },
          data: {
            activeVersion: nextVersion
          }
        })

        return toSecretEnvelopeVersion(createdVersion)
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getActiveSecretEnvelope(rawInput: GetSecretEnvelopeInput): Promise<SecretEnvelopeVersion | null> {
    const input = GetSecretEnvelopeInputSchema.parse(rawInput)

    try {
      const secret = await this.db.secret.findUnique({
        where: {
          secretRef: input.secret_ref
        },
        select: {
          activeVersion: true
        }
      })

      if (!secret) {
        return null
      }

      return this.getSecretEnvelopeVersion({
        secret_ref: input.secret_ref,
        version: secret.activeVersion
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getSecretEnvelopeVersion(rawInput: GetSecretEnvelopeInput): Promise<SecretEnvelopeVersion | null> {
    const input = GetSecretEnvelopeInputSchema.parse(rawInput)

    if (input.version === undefined) {
      throw new DbRepositoryError('validation_error', 'version is required for version lookup')
    }

    try {
      const record = await this.db.secretVersion.findUnique({
        where: {
          secretRef_version: {
            secretRef: input.secret_ref,
            version: input.version
          }
        },
        include: {
          secret: {
            select: {
              tenantId: true,
              integrationId: true,
              type: true
            }
          }
        }
      })

      if (!record) {
        return null
      }

      return toSecretEnvelopeVersion(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async setActiveSecretEnvelopeVersion(
    rawInput: SetActiveSecretEnvelopeVersionInput
  ): Promise<void> {
    const input = SetActiveSecretEnvelopeVersionInputSchema.parse(rawInput)

    try {
      const targetVersion = await this.db.secretVersion.findUnique({
        where: {
          secretRef_version: {
            secretRef: input.secret_ref,
            version: input.version
          }
        },
        select: {
          id: true
        }
      })

      if (!targetVersion) {
        throw new DbRepositoryError('not_found', 'Secret version does not exist')
      }

      await this.db.secret.update({
        where: {
          secretRef: input.secret_ref
        },
        data: {
          activeVersion: input.version
        }
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listSecretEnvelopeVersions(input: {secret_ref: string}): Promise<SecretEnvelopeVersion[]> {
    const secretRef = input.secret_ref.trim()
    if (secretRef.length === 0) {
      throw new DbRepositoryError('validation_error', 'secret_ref cannot be empty')
    }

    try {
      const records = await this.db.secretVersion.findMany({
        where: {
          secretRef
        },
        include: {
          secret: {
            select: {
              tenantId: true,
              integrationId: true,
              type: true
            }
          }
        },
        orderBy: {
          version: 'asc'
        }
      })

      return records.map(toSecretEnvelopeVersion)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async createManifestSigningKeyRecord(
    rawInput: CreateManifestSigningKeyRecordInput,
    context?: RepositoryOperationContext
  ): Promise<ManifestSigningKeyRecord> {
    const input = CreateManifestSigningKeyRecordInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'manifestSigningKey',
          method: 'create'
        }
      ])

      const record = await dbClient.manifestSigningKey.create({
        data: {
          kid: input.kid,
          alg: input.alg,
          publicJwk: input.public_jwk,
          privateKeyRef: input.private_key_ref,
          status: 'retired',
          createdAt: new Date(input.created_at),
          retiredAt: new Date(input.created_at)
        }
      })

      return toManifestSigningKeyRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async setActiveManifestSigningKey(
    rawInput: SetActiveManifestSigningKeyInput,
    context?: RepositoryOperationContext
  ): Promise<ManifestSigningKeyRecord> {
    const input = SetActiveManifestSigningKeyInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'manifestSigningKey',
          method: 'findUnique'
        },
        {
          model: 'manifestSigningKey',
          method: 'update'
        }
      ])

      const existing = await dbClient.manifestSigningKey.findUnique({
        where: {
          kid: input.kid
        }
      })

      if (!existing) {
        throw new DbRepositoryError('not_found', 'Manifest signing key does not exist')
      }

      if (existing.status === 'revoked') {
        throw new DbRepositoryError('state_transition_invalid', 'Manifest signing key is revoked')
      }

      const record = await dbClient.manifestSigningKey.update({
        where: {
          kid: input.kid
        },
        data: {
          status: 'active',
          activatedAt: new Date(input.activated_at),
          retiredAt: null,
          revokedAt: null
        }
      })

      return toManifestSigningKeyRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async retireManifestSigningKey(
    rawInput: RetireManifestSigningKeyInput,
    context?: RepositoryOperationContext
  ): Promise<ManifestSigningKeyRecord> {
    const input = RetireManifestSigningKeyInputSchema.parse(rawInput)
    return this.transitionManifestSigningKeyStatus(
      {
        kid: input.kid,
        status: 'retired',
        at: input.retired_at
      },
      context
    )
  }

  public async revokeManifestSigningKey(
    rawInput: RevokeManifestSigningKeyInput,
    context?: RepositoryOperationContext
  ): Promise<ManifestSigningKeyRecord> {
    const input = RevokeManifestSigningKeyInputSchema.parse(rawInput)
    return this.transitionManifestSigningKeyStatus(
      {
        kid: input.kid,
        status: 'revoked',
        at: input.revoked_at
      },
      context
    )
  }

  public async transitionManifestSigningKeyStatus(
    rawInput: TransitionManifestSigningKeyStatusInput,
    context?: RepositoryOperationContext
  ): Promise<ManifestSigningKeyRecord> {
    const input = TransitionManifestSigningKeyStatusInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'manifestSigningKey',
          method: 'findUnique'
        },
        {
          model: 'manifestSigningKey',
          method: 'update'
        }
      ])

      const existing = await dbClient.manifestSigningKey.findUnique({
        where: {
          kid: input.kid
        }
      })

      if (!existing) {
        throw new DbRepositoryError('not_found', 'Manifest signing key does not exist')
      }

      if (existing.status === 'revoked' && input.status !== 'revoked') {
        throw new DbRepositoryError('state_transition_invalid', 'Manifest signing key is revoked')
      }

      if (existing.status === input.status) {
        return toManifestSigningKeyRecord(existing)
      }

      const data =
        input.status === 'retired'
          ? {status: 'retired' as const, retiredAt: new Date(input.at)}
          : {status: 'revoked' as const, revokedAt: new Date(input.at)}

      const record = await dbClient.manifestSigningKey.update({
        where: {
          kid: input.kid
        },
        data
      })

      return toManifestSigningKeyRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getActiveManifestSigningKeyRecord(
    context?: RepositoryOperationContext
  ): Promise<ManifestSigningKeyRecord | null> {
    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'manifestSigningKey',
          method: 'findFirst'
        }
      ])

      const record = await dbClient.manifestSigningKey.findFirst({
        where: {
          status: 'active'
        },
        orderBy: [
          {
            activatedAt: 'desc'
          },
          {
            createdAt: 'desc'
          },
          {
            kid: 'asc'
          }
        ]
      })

      if (!record) {
        return null
      }

      return toManifestSigningKeyRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async listManifestVerificationKeysWithEtag(
    context?: RepositoryOperationContext
  ): Promise<ManifestVerificationKeysetWithEtag | null> {
    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'manifestSigningKey',
          method: 'findMany'
        },
        {
          model: 'manifestKeysetMetadata',
          method: 'findUnique'
        }
      ])

      const metadata = await dbClient.manifestKeysetMetadata.findUnique({
        where: {
          keysetName: MANIFEST_KEYSET_NAME
        }
      })

      if (!metadata) {
        return null
      }

      const keys = await dbClient.manifestSigningKey.findMany({
        where: {
          status: {
            in: ['active', 'retired']
          }
        },
        orderBy: [
          {
            status: 'asc'
          },
          {
            createdAt: 'desc'
          },
          {
            kid: 'asc'
          }
        ],
        select: {
          publicJwk: true
        }
      })

      if (keys.length === 0) {
        throw new DbRepositoryError('not_found', 'No manifest verification keys are available')
      }

      return ManifestVerificationKeysetWithEtagSchema.parse({
        manifest_keys: {
          keys: keys.map(key => key.publicJwk)
        },
        etag: metadata.etag,
        generated_at: metadata.generatedAt.toISOString(),
        max_age_seconds: metadata.maxAgeSeconds
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async persistManifestKeysetMetadata(
    rawInput: PersistManifestKeysetMetadataInput,
    context?: RepositoryOperationContext
  ): Promise<void> {
    const input = PersistManifestKeysetMetadataInputSchema.parse(rawInput)

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'manifestSigningKey',
          method: 'findFirst'
        },
        {
          model: 'manifestKeysetMetadata',
          method: 'upsert'
        }
      ])

      const key = await dbClient.manifestSigningKey.findFirst({
        where: {
          status: {
            in: ['active', 'retired']
          }
        },
        select: {
          kid: true
        }
      })

      if (!key) {
        throw new DbRepositoryError(
          'not_found',
          'Cannot persist manifest keyset metadata without at least one active or retired key'
        )
      }

      await dbClient.manifestKeysetMetadata.upsert({
        where: {
          keysetName: MANIFEST_KEYSET_NAME
        },
        create: {
          keysetName: MANIFEST_KEYSET_NAME,
          etag: input.etag,
          generatedAt: new Date(input.generated_at),
          maxAgeSeconds: input.max_age_seconds
        },
        update: {
          etag: input.etag,
          generatedAt: new Date(input.generated_at),
          maxAgeSeconds: input.max_age_seconds
        }
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getCryptoVerificationDefaultsByTenant(
    rawInput: GetCryptoVerificationDefaultsByTenantInput,
    context?: RepositoryOperationContext
  ): Promise<CryptoVerificationDefaults> {
    const tenantId = rawInput.tenant_id.trim()
    const parsedInput = GetCryptoVerificationDefaultsByTenantInputSchema.safeParse({
      tenant_id: tenantId
    })
    if (!parsedInput.success) {
      throw new DbRepositoryError(
        'validation_error',
        parsedInput.error.issues[0]?.message ?? 'Invalid crypto verification defaults lookup input'
      )
    }
    const input = parsedInput.data

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'cryptoVerificationDefaults',
          method: 'findUnique'
        }
      ])

      const record = await dbClient.cryptoVerificationDefaults.findUnique({
        where: {
          tenantId: input.tenant_id
        }
      })

      if (!record) {
        return CryptoVerificationDefaultsSchema.parse({
          tenant_id: input.tenant_id,
          require_temporal_validity: true,
          max_clock_skew_seconds: 0
        })
      }

      return toCryptoVerificationDefaults(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async upsertCryptoVerificationDefaults(
    rawInput: UpsertCryptoVerificationDefaultsInput,
    context?: RepositoryOperationContext
  ): Promise<CryptoVerificationDefaults> {
    const tenantId = rawInput.tenant_id.trim()
    const parsedInput = UpsertCryptoVerificationDefaultsInputSchema.safeParse({
      ...rawInput,
      tenant_id: tenantId
    })
    if (!parsedInput.success) {
      throw new DbRepositoryError(
        'validation_error',
        parsedInput.error.issues[0]?.message ?? 'Invalid crypto verification defaults input'
      )
    }
    const input = parsedInput.data

    try {
      const dbClient = resolveRepositoryDbClient(this.db, context, [
        {
          model: 'cryptoVerificationDefaults',
          method: 'upsert'
        }
      ])

      const record = await dbClient.cryptoVerificationDefaults.upsert({
        where: {
          tenantId: input.tenant_id
        },
        create: {
          tenantId: input.tenant_id,
          requireTemporalValidity: input.require_temporal_validity,
          maxClockSkewSeconds: input.max_clock_skew_seconds
        },
        update: {
          requireTemporalValidity: input.require_temporal_validity,
          maxClockSkewSeconds: input.max_clock_skew_seconds
        }
      })

      return toCryptoVerificationDefaults(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}

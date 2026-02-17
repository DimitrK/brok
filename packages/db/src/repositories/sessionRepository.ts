import {
  SessionLookupInputSchema,
  SessionRecordSchema,
  type SessionRecord
} from '../contracts.js'
import {DbRepositoryError, mapDatabaseError} from '../errors.js'
import type {DatabaseClient} from '../types.js'

const toSessionRecord = (record: {
  sessionId: string
  workloadId: string
  tenantId: string
  certFingerprint256: string
  tokenHash: string
  expiresAt: Date
  dpopJkt: string | null
  scopes: unknown
}): SessionRecord => {
  const scopes = Array.isArray(record.scopes)
    ? record.scopes.filter(value => typeof value === 'string')
    : []

  return SessionRecordSchema.parse({
    sessionId: record.sessionId,
    workloadId: record.workloadId,
    tenantId: record.tenantId,
    certFingerprint256: record.certFingerprint256,
    tokenHash: record.tokenHash,
    expiresAt: record.expiresAt.toISOString(),
    ...(record.dpopJkt ? {dpopKeyThumbprint: record.dpopJkt} : {}),
    ...(scopes.length > 0 ? {scopes} : {})
  })
}

export class SessionRepository {
  public constructor(private readonly db: DatabaseClient) {}

  public async upsertSession(rawSession: SessionRecord): Promise<SessionRecord> {
    const session = SessionRecordSchema.parse(rawSession)

    try {
      const upserted = await this.db.workloadSession.upsert({
        where: {
          sessionId: session.sessionId
        },
        create: {
          sessionId: session.sessionId,
          workloadId: session.workloadId,
          tenantId: session.tenantId,
          certFingerprint256: session.certFingerprint256,
          tokenHash: session.tokenHash,
          dpopJkt: session.dpopKeyThumbprint,
          scopes: session.scopes ?? [],
          expiresAt: new Date(session.expiresAt)
        },
        update: {
          workloadId: session.workloadId,
          tenantId: session.tenantId,
          certFingerprint256: session.certFingerprint256,
          tokenHash: session.tokenHash,
          dpopJkt: session.dpopKeyThumbprint,
          scopes: session.scopes ?? [],
          expiresAt: new Date(session.expiresAt),
          revokedAt: null
        }
      })

      return toSessionRecord(upserted)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async getSessionByTokenHash(input: {token_hash: string}): Promise<SessionRecord | null> {
    const parsedInput = SessionLookupInputSchema.parse(input)

    try {
      const now = new Date()
      const record = await this.db.workloadSession.findFirst({
        where: {
          tokenHash: parsedInput.token_hash,
          revokedAt: null,
          expiresAt: {
            gt: now
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      })

      if (!record) {
        return null
      }

      return toSessionRecord(record)
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async revokeSessionById(input: {session_id: string}): Promise<void> {
    const sessionId = input.session_id.trim()
    if (sessionId.length === 0) {
      throw new DbRepositoryError('validation_error', 'session_id cannot be empty')
    }

    try {
      await this.db.workloadSession.update({
        where: {
          sessionId
        },
        data: {
          revokedAt: new Date()
        }
      })
    } catch (error) {
      return mapDatabaseError(error)
    }
  }

  public async deleteExpiredSessions(input?: {now?: Date}): Promise<number> {
    try {
      const result = await this.db.workloadSession.deleteMany({
        where: {
          expiresAt: {
            lte: input?.now ?? new Date()
          }
        }
      })

      return result.count
    } catch (error) {
      return mapDatabaseError(error)
    }
  }
}

import {z} from 'zod'

import {WorkloadSchema} from './generated/schemas'

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

export const jwkSchema = z.record(z.string(), z.unknown())

export const dpopClaimsSchema = z
  .object({
    htm: z.string().min(1),
    htu: z.string().min(1),
    iat: z.number().int(),
    jti: z.string().min(1)
  })
  .loose()

export const dpopPayloadSchema = dpopClaimsSchema.extend({
  ath: z.string().optional()
})

export type DpopClaimsContract = z.infer<typeof dpopClaimsSchema>
export type DpopPayloadContract = z.infer<typeof dpopPayloadSchema>

const canonicalWorkloadRecordSchema = WorkloadSchema.pick({
  workload_id: true,
  tenant_id: true,
  enabled: true,
  ip_allowlist: true
}).loose()

export const workloadRecordSchema = z
  .preprocess(value => {
    if (!isRecord(value)) {
      return value
    }

    return {
      ...value,
      workload_id: value.workload_id ?? value.workloadId,
      tenant_id: value.tenant_id ?? value.tenantId,
      ip_allowlist: value.ip_allowlist ?? value.ipAllowlist
    }
  }, canonicalWorkloadRecordSchema)
  .transform(value => ({
    workloadId: value.workload_id,
    tenantId: value.tenant_id,
    enabled: value.enabled,
    ...(value.ip_allowlist ? {ipAllowlist: value.ip_allowlist} : {})
  }))

export type WorkloadRecordContract = z.infer<typeof workloadRecordSchema>

export const peerCertificateSchema = z
  .object({
    subjectaltname: z.string().optional(),
    ext_key_usage: z.union([z.string(), z.array(z.string())]).optional(),
    fingerprint256: z.string().optional()
  })
  .loose()

export type PeerCertificateContract = z.infer<typeof peerCertificateSchema>

export const parsedCsrSchema = z
  .object({
    sanUris: z.array(z.string().min(1)),
    extKeyUsageOids: z.array(z.string().min(1))
  })
  .loose()

export type ParsedCsrContract = z.infer<typeof parsedCsrSchema>

import {z} from 'zod';

const EnvironmentSchema = z.enum(['development', 'test', 'production']);

export const EbpfInterceptorConfigSchema = z
  .object({
    environment: EnvironmentSchema.default('development'),
    rejectUnknownReasonCodes: z.boolean().default(true),
    controlSocketPath: z.string().min(1).default('/var/run/broker-interceptor-ebpf/agentd.sock'),
    controlSocketDirMode: z.number().int().min(0).max(0o777).default(0o750),
    controlSocketFileMode: z.number().int().min(0).max(0o777).default(0o660),
    controlSocketOwnerUid: z.number().int().nonnegative().default(0),
    controlSocketOwnerGid: z.number().int().nonnegative().default(0),
    privilegedControllerUids: z.array(z.number().int().nonnegative()).default([]),
    privilegedControllerGids: z.array(z.number().int().nonnegative()).default([])
  })
  .strict();

export type EbpfInterceptorConfig = z.infer<typeof EbpfInterceptorConfigSchema>;

export function parseEbpfInterceptorConfig(input: unknown): EbpfInterceptorConfig {
  return EbpfInterceptorConfigSchema.parse(input);
}

export function shouldFailClosedOnUnknownReasonCode(config: EbpfInterceptorConfig): boolean {
  if (config.environment === 'production') {
    return true;
  }

  return config.rejectUnknownReasonCodes;
}

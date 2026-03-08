import path from 'node:path';

import {z} from 'zod';

const optionalString = z.preprocess(value => {
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}, z.string().optional());

const integerFromEnv = z.preprocess(value => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return value;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? value : parsed;
}, z.number().int().positive());

const booleanFromEnv = z.preprocess(value => {
  if (typeof value !== 'string') {
    return value;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1') {
    return true;
  }
  if (normalized === 'false' || normalized === '0') {
    return false;
  }

  return value;
}, z.boolean());

const endpointSchema = z
  .string()
  .url()
  .transform(value => value.replace(/\/+$/u, ''));
const prefixSchema = z
  .string()
  .trim()
  .min(1)
  .transform(value => value.replace(/^\/+/u, '').replace(/\/+$/u, ''));

const envSchema = z
  .object({
    BACKUP_WORKLOAD_BROKER_URL: endpointSchema,
    BACKUP_WORKLOAD_WORKLOAD_ID: z.string().trim().min(1),
    BACKUP_WORKLOAD_S3_INTEGRATION_ID: z.string().trim().min(1),
    BACKUP_WORKLOAD_SESSION_TOKEN: optionalString,
    BACKUP_WORKLOAD_MTLS_CERT_PATH: optionalString,
    BACKUP_WORKLOAD_MTLS_KEY_PATH: optionalString,
    BACKUP_WORKLOAD_MTLS_CA_PATH: optionalString,
    BACKUP_WORKLOAD_SESSION_TTL_SECONDS: integerFromEnv.optional(),
    BACKUP_WORKLOAD_S3_ENDPOINT: endpointSchema,
    BACKUP_WORKLOAD_S3_PREFIX: prefixSchema.default('backups/broker'),
    BACKUP_WORKLOAD_ENCRYPTION_KEY_B64: z.string().min(1),
    BACKUP_WORKLOAD_DATABASE_URL: z.string().min(1),
    BACKUP_WORKLOAD_DB_DUMP_BIN: z.string().default('pg_dump'),
    BACKUP_WORKLOAD_DB_DUMP_CONTAINER: optionalString,
    BACKUP_WORKLOAD_DB_RESTORE_BIN: z.string().default('psql'),
    BACKUP_WORKLOAD_STAGING_DIR: optionalString,
    BACKUP_WORKLOAD_CHUNK_SIZE_BYTES: integerFromEnv.default(512 * 1024),
    BACKUP_WORKLOAD_MANIFEST_FILENAME: z.string().default('manifest.json'),
    BACKUP_WORKLOAD_ALLOW_MISSING_CRITICAL_SECRETS: booleanFromEnv.default(false),
    BACKUP_WORKLOAD_BROKER_API_CERTS_DIR: optionalString,
    BACKUP_WORKLOAD_ADMIN_CA_CERT_PATH: optionalString,
    BACKUP_WORKLOAD_ADMIN_CA_KEY_PATH: optionalString,
    BACKUP_WORKLOAD_RESTORE_VERSION: optionalString,
    BACKUP_WORKLOAD_RESTORE_CONFIRM: optionalString,
    BACKUP_WORKLOAD_RESTORE_BROKER_API_CERTS_DIR: optionalString,
    BACKUP_WORKLOAD_RESTORE_ADMIN_CA_CERT_PATH: optionalString,
    BACKUP_WORKLOAD_RESTORE_ADMIN_CA_KEY_PATH: optionalString,
    BROKER_ADMIN_API_SECRET_KEY_B64: optionalString,
    BROKER_ADMIN_API_SECRET_KEY_ID: optionalString,
    BROKER_API_SECRET_KEY_B64: optionalString,
    BROKER_API_SECRET_KEY_ID: optionalString,
    BROKER_ADMIN_API_MANIFEST_KEYS_JSON: optionalString,
    BROKER_ADMIN_API_CERT_ISSUER_MODE: optionalString,
    BROKER_ADMIN_API_LOCAL_CA_CERT_PATH: optionalString,
    BROKER_ADMIN_API_LOCAL_CA_KEY_PATH: optionalString,
    BROKER_ADMIN_API_VAULT_ADDR: optionalString,
    BROKER_ADMIN_API_VAULT_PKI_MOUNT: optionalString,
    BROKER_ADMIN_API_VAULT_PKI_ROLE: optionalString
  })
  .strict()
  .superRefine((value, context) => {
    const hasSessionToken = typeof value.BACKUP_WORKLOAD_SESSION_TOKEN === 'string';
    const hasMtlsCredentials =
      typeof value.BACKUP_WORKLOAD_MTLS_CERT_PATH === 'string' &&
      typeof value.BACKUP_WORKLOAD_MTLS_KEY_PATH === 'string';

    if (!hasSessionToken && !hasMtlsCredentials) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'Provide either BACKUP_WORKLOAD_SESSION_TOKEN or both BACKUP_WORKLOAD_MTLS_CERT_PATH and BACKUP_WORKLOAD_MTLS_KEY_PATH.'
      });
    }
  });

const envKeys = [
  'BACKUP_WORKLOAD_BROKER_URL',
  'BACKUP_WORKLOAD_WORKLOAD_ID',
  'BACKUP_WORKLOAD_S3_INTEGRATION_ID',
  'BACKUP_WORKLOAD_SESSION_TOKEN',
  'BACKUP_WORKLOAD_MTLS_CERT_PATH',
  'BACKUP_WORKLOAD_MTLS_KEY_PATH',
  'BACKUP_WORKLOAD_MTLS_CA_PATH',
  'BACKUP_WORKLOAD_SESSION_TTL_SECONDS',
  'BACKUP_WORKLOAD_S3_ENDPOINT',
  'BACKUP_WORKLOAD_S3_PREFIX',
  'BACKUP_WORKLOAD_ENCRYPTION_KEY_B64',
  'BACKUP_WORKLOAD_DATABASE_URL',
  'BACKUP_WORKLOAD_DB_DUMP_BIN',
  'BACKUP_WORKLOAD_DB_DUMP_CONTAINER',
  'BACKUP_WORKLOAD_DB_RESTORE_BIN',
  'BACKUP_WORKLOAD_STAGING_DIR',
  'BACKUP_WORKLOAD_CHUNK_SIZE_BYTES',
  'BACKUP_WORKLOAD_MANIFEST_FILENAME',
  'BACKUP_WORKLOAD_ALLOW_MISSING_CRITICAL_SECRETS',
  'BACKUP_WORKLOAD_BROKER_API_CERTS_DIR',
  'BACKUP_WORKLOAD_ADMIN_CA_CERT_PATH',
  'BACKUP_WORKLOAD_ADMIN_CA_KEY_PATH',
  'BACKUP_WORKLOAD_RESTORE_VERSION',
  'BACKUP_WORKLOAD_RESTORE_CONFIRM',
  'BACKUP_WORKLOAD_RESTORE_BROKER_API_CERTS_DIR',
  'BACKUP_WORKLOAD_RESTORE_ADMIN_CA_CERT_PATH',
  'BACKUP_WORKLOAD_RESTORE_ADMIN_CA_KEY_PATH',
  'BROKER_ADMIN_API_SECRET_KEY_B64',
  'BROKER_ADMIN_API_SECRET_KEY_ID',
  'BROKER_API_SECRET_KEY_B64',
  'BROKER_API_SECRET_KEY_ID',
  'BROKER_ADMIN_API_MANIFEST_KEYS_JSON',
  'BROKER_ADMIN_API_CERT_ISSUER_MODE',
  'BROKER_ADMIN_API_LOCAL_CA_CERT_PATH',
  'BROKER_ADMIN_API_LOCAL_CA_KEY_PATH',
  'BROKER_ADMIN_API_VAULT_ADDR',
  'BROKER_ADMIN_API_VAULT_PKI_MOUNT',
  'BROKER_ADMIN_API_VAULT_PKI_ROLE'
] as const;

const pickConfigEnv = (env: NodeJS.ProcessEnv) =>
  Object.fromEntries(envKeys.map(key => [key, env[key]])) as Record<(typeof envKeys)[number], string | undefined>;

const parseEncryptionKey = (raw: string) => {
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32) {
    throw new Error('BACKUP_WORKLOAD_ENCRYPTION_KEY_B64 must decode to exactly 32 bytes');
  }
  return decoded;
};

export type BackupWorkloadConfig = {
  broker: {
    brokerUrl: string;
    workloadId: string;
    s3IntegrationId: string;
    sessionToken?: string;
    mtlsCertPath?: string;
    mtlsKeyPath?: string;
    mtlsCaPath?: string;
    sessionTtlSeconds?: number;
  };
  s3Endpoint: string;
  s3Prefix: string;
  manifestFilename: string;
  encryptionKey: Buffer;
  databaseUrl: string;
  dumpBinary: string;
  dumpContainer?: string;
  restoreBinary: string;
  stagingRoot: string;
  chunkSizeBytes: number;
  allowMissingCriticalSecrets: boolean;
  brokerApiCertsDir?: string;
  adminCertificateIssuer: {
    mode?: string;
    localCaCertPath?: string;
    localCaKeyPath?: string;
    vaultAddr?: string;
    vaultPkiMount?: string;
    vaultPkiRole?: string;
  };
  sharedSecrets: {
    brokerAdminApiSecretKeyB64?: string;
    brokerAdminApiSecretKeyId?: string;
    brokerApiSecretKeyB64?: string;
    brokerApiSecretKeyId?: string;
    manifestKeysJson?: string;
  };
  restore: {
    version?: string;
    confirmed: boolean;
    brokerApiCertsDir?: string;
    adminCaCertPath?: string;
    adminCaKeyPath?: string;
  };
};

export const loadConfig = (env: NodeJS.ProcessEnv = process.env): BackupWorkloadConfig => {
  const parsed = envSchema.parse(pickConfigEnv(env));

  return {
    broker: {
      brokerUrl: parsed.BACKUP_WORKLOAD_BROKER_URL,
      workloadId: parsed.BACKUP_WORKLOAD_WORKLOAD_ID,
      s3IntegrationId: parsed.BACKUP_WORKLOAD_S3_INTEGRATION_ID,
      sessionToken: parsed.BACKUP_WORKLOAD_SESSION_TOKEN,
      mtlsCertPath: parsed.BACKUP_WORKLOAD_MTLS_CERT_PATH
        ? path.resolve(process.cwd(), parsed.BACKUP_WORKLOAD_MTLS_CERT_PATH)
        : undefined,
      mtlsKeyPath: parsed.BACKUP_WORKLOAD_MTLS_KEY_PATH
        ? path.resolve(process.cwd(), parsed.BACKUP_WORKLOAD_MTLS_KEY_PATH)
        : undefined,
      mtlsCaPath: parsed.BACKUP_WORKLOAD_MTLS_CA_PATH
        ? path.resolve(process.cwd(), parsed.BACKUP_WORKLOAD_MTLS_CA_PATH)
        : undefined,
      sessionTtlSeconds: parsed.BACKUP_WORKLOAD_SESSION_TTL_SECONDS
    },
    s3Endpoint: parsed.BACKUP_WORKLOAD_S3_ENDPOINT,
    s3Prefix: parsed.BACKUP_WORKLOAD_S3_PREFIX,
    manifestFilename: parsed.BACKUP_WORKLOAD_MANIFEST_FILENAME,
    encryptionKey: parseEncryptionKey(parsed.BACKUP_WORKLOAD_ENCRYPTION_KEY_B64),
    databaseUrl: parsed.BACKUP_WORKLOAD_DATABASE_URL,
    dumpBinary: parsed.BACKUP_WORKLOAD_DB_DUMP_BIN,
    dumpContainer: parsed.BACKUP_WORKLOAD_DB_DUMP_CONTAINER,
    restoreBinary: parsed.BACKUP_WORKLOAD_DB_RESTORE_BIN,
    stagingRoot: parsed.BACKUP_WORKLOAD_STAGING_DIR ?? path.resolve(process.cwd(), '.backup-workload'),
    chunkSizeBytes: parsed.BACKUP_WORKLOAD_CHUNK_SIZE_BYTES,
    allowMissingCriticalSecrets: parsed.BACKUP_WORKLOAD_ALLOW_MISSING_CRITICAL_SECRETS,
    brokerApiCertsDir: parsed.BACKUP_WORKLOAD_BROKER_API_CERTS_DIR,
    adminCertificateIssuer: {
      mode: parsed.BROKER_ADMIN_API_CERT_ISSUER_MODE,
      localCaCertPath: parsed.BACKUP_WORKLOAD_ADMIN_CA_CERT_PATH ?? parsed.BROKER_ADMIN_API_LOCAL_CA_CERT_PATH,
      localCaKeyPath: parsed.BACKUP_WORKLOAD_ADMIN_CA_KEY_PATH ?? parsed.BROKER_ADMIN_API_LOCAL_CA_KEY_PATH,
      vaultAddr: parsed.BROKER_ADMIN_API_VAULT_ADDR,
      vaultPkiMount: parsed.BROKER_ADMIN_API_VAULT_PKI_MOUNT,
      vaultPkiRole: parsed.BROKER_ADMIN_API_VAULT_PKI_ROLE
    },
    sharedSecrets: {
      brokerAdminApiSecretKeyB64: parsed.BROKER_ADMIN_API_SECRET_KEY_B64,
      brokerAdminApiSecretKeyId: parsed.BROKER_ADMIN_API_SECRET_KEY_ID,
      brokerApiSecretKeyB64: parsed.BROKER_API_SECRET_KEY_B64,
      brokerApiSecretKeyId: parsed.BROKER_API_SECRET_KEY_ID,
      manifestKeysJson: parsed.BROKER_ADMIN_API_MANIFEST_KEYS_JSON
    },
    restore: {
      version: parsed.BACKUP_WORKLOAD_RESTORE_VERSION,
      confirmed: parsed.BACKUP_WORKLOAD_RESTORE_CONFIRM === 'RESTORE',
      brokerApiCertsDir: parsed.BACKUP_WORKLOAD_RESTORE_BROKER_API_CERTS_DIR,
      adminCaCertPath: parsed.BACKUP_WORKLOAD_RESTORE_ADMIN_CA_CERT_PATH,
      adminCaKeyPath: parsed.BACKUP_WORKLOAD_RESTORE_ADMIN_CA_KEY_PATH
    }
  };
};

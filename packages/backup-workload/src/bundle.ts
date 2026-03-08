import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createGunzip, createGzip} from 'node:zlib';
import {createReadStream, createWriteStream} from 'node:fs';
import {promises as fs} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pipeline} from 'node:stream/promises';

import type {BackupWorkloadConfig} from './config.js';
import {buildDatabaseClientCommand, ensureDumpBinaryCompatibility} from './postgres-client.js';

export type BackupChunkDescriptor = {
  index: number;
  key: string;
  size_bytes: number;
  sha256: string;
};

export type BackupManifest = {
  schema_version: 1;
  backup_id: string;
  version: number;
  created_at: string;
  storage: {
    manifest_key: string;
    total_chunks: number;
    total_bytes: number;
    chunks: BackupChunkDescriptor[];
  };
  encryption: {
    algorithm: 'aes-256-gcm';
    iv_b64: string;
    auth_tag_b64: string;
    ciphertext_sha256: string;
  };
  included_artifacts: {
    database_dump_path: string;
    broker_admin_local_ca_included: boolean;
    broker_api_certs_included: boolean;
    shared_secret_snapshot_included: boolean;
  };
  external_dependencies: {
    broker_admin_certificate_issuer_mode?: string;
    vault_addr?: string;
    vault_pki_mount?: string;
    vault_pki_role?: string;
  };
};

const copyRestoredFile = async ({sourcePath, targetPath}: {sourcePath: string; targetPath?: string}) => {
  if (!targetPath) {
    return false;
  }

  await ensureDirectory(path.dirname(targetPath));
  await fs.copyFile(sourcePath, targetPath);
  return true;
};

const runCommand = ({
  command,
  args,
  cwd,
  stdin,
  stdout
}: {
  command: string;
  args: string[];
  cwd?: string;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
}) =>
  new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: process.env,
      stdio: ['pipe', stdout ? 'pipe' : 'inherit', 'inherit']
    });

    if (!child.stdin) {
      reject(new Error(`${command} did not expose stdin`));
      return;
    }

    if (stdin) {
      stdin.pipe(child.stdin);
    } else {
      child.stdin.end();
    }

    if (stdout) {
      if (!child.stdout) {
        reject(new Error(`${command} did not expose stdout`));
        return;
      }

      child.stdout.pipe(stdout);
    }

    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`${command} exited with code ${String(code)}`));
    });
  });

const ensureDirectory = async (targetPath: string) => {
  await fs.mkdir(targetPath, {recursive: true});
};

const sha256Hex = (value: Buffer) => createHash('sha256').update(value).digest('hex');

const writeJsonFile = async (targetPath: string, value: unknown) =>
  fs.writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');

const maybeCopyFile = async ({sourcePath, targetPath}: {sourcePath?: string; targetPath: string}) => {
  if (!sourcePath) {
    return false;
  }

  await fs.copyFile(sourcePath, targetPath);
  return true;
};

const ensureCriticalSecrets = (config: BackupWorkloadConfig) => {
  const missing = [
    !config.sharedSecrets.brokerAdminApiSecretKeyB64 ? 'BROKER_ADMIN_API_SECRET_KEY_B64' : null,
    !config.sharedSecrets.brokerApiSecretKeyB64 ? 'BROKER_API_SECRET_KEY_B64' : null
  ].filter((value): value is string => value !== null);

  if (missing.length > 0 && !config.allowMissingCriticalSecrets) {
    throw new Error(
      `Refusing to continue without critical restore secrets: ${missing.join(', ')}. Set BACKUP_WORKLOAD_ALLOW_MISSING_CRITICAL_SECRETS=true to override.`
    );
  }
};

const dumpDatabase = async ({
  dumpBinary,
  dumpContainer,
  sqlClientBinary,
  databaseUrl,
  targetPath
}: {
  dumpBinary: string;
  dumpContainer?: string;
  sqlClientBinary: string;
  databaseUrl: string;
  targetPath: string;
}) => {
  const dumpCommand = buildDatabaseClientCommand({
    binary: dumpBinary,
    container: dumpContainer
  });
  const sqlClientCommand = buildDatabaseClientCommand({
    binary: sqlClientBinary,
    container: dumpContainer
  });

  await ensureDumpBinaryCompatibility({
    databaseUrl,
    dumpCommand,
    sqlClientCommand
  });

  const gzipStream = createGzip({level: 9});
  const outputStream = createWriteStream(targetPath);

  const dumpProcess = spawn(
    dumpCommand.command,
    [...dumpCommand.argsPrefix, '--dbname', databaseUrl, '--no-owner', '--no-privileges', '--format=plain'],
    {
      env: process.env,
      stdio: ['ignore', 'pipe', 'inherit']
    }
  );

  if (!dumpProcess.stdout) {
    throw new Error('pg_dump did not provide stdout for database export');
  }

  const dumpCompletion = new Promise<void>((resolve, reject) => {
    dumpProcess.on('error', reject);
    dumpProcess.on('close', code => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`${dumpCommand.displayName} exited with code ${String(code)}`));
    });
  });

  await Promise.all([pipeline(dumpProcess.stdout, gzipStream, outputStream), dumpCompletion]);
};

const restoreDatabase = async ({
  restoreBinary,
  databaseUrl,
  dumpPath
}: {
  restoreBinary: string;
  databaseUrl: string;
  dumpPath: string;
}) =>
  runCommand({
    command: restoreBinary,
    args: ['--dbname', databaseUrl, '--single-transaction', '--set', 'ON_ERROR_STOP=1'],
    stdin: createReadStream(dumpPath).pipe(createGunzip())
  });

const createTarball = async ({sourceDir, targetPath}: {sourceDir: string; targetPath: string}) =>
  runCommand({
    command: 'tar',
    args: ['-czf', targetPath, '-C', sourceDir, '.']
  });

const extractTarball = async ({archivePath, targetDir}: {archivePath: string; targetDir: string}) => {
  await ensureDirectory(targetDir);
  await runCommand({
    command: 'tar',
    args: ['-xzf', archivePath, '-C', targetDir]
  });
};

export const createBackupBundle = async ({
  config,
  backupId,
  version,
  timestamp
}: {
  config: BackupWorkloadConfig;
  backupId: string;
  version: number;
  timestamp: string;
}) => {
  ensureCriticalSecrets(config);

  const workspaceRoot = await fs.mkdtemp(path.join(config.stagingRoot, `${backupId}-`));
  const bundleRoot = path.join(workspaceRoot, 'bundle');
  await ensureDirectory(bundleRoot);

  const databaseDumpRelativePath = 'database/database.sql.gz';
  const databaseDumpPath = path.join(bundleRoot, databaseDumpRelativePath);
  await ensureDirectory(path.dirname(databaseDumpPath));
  await dumpDatabase({
    dumpBinary: config.dumpBinary,
    dumpContainer: config.dumpContainer,
    sqlClientBinary: config.restoreBinary,
    databaseUrl: config.databaseUrl,
    targetPath: databaseDumpPath
  });

  let brokerAdminLocalCaIncluded = false;
  if (config.adminCertificateIssuer.mode === 'local') {
    const localCaDir = path.join(bundleRoot, 'broker-admin-local-ca');
    await ensureDirectory(localCaDir);
    brokerAdminLocalCaIncluded =
      (await maybeCopyFile({
        sourcePath: config.adminCertificateIssuer.localCaCertPath,
        targetPath: path.join(localCaDir, 'ca.crt')
      })) &&
      (await maybeCopyFile({
        sourcePath: config.adminCertificateIssuer.localCaKeyPath,
        targetPath: path.join(localCaDir, 'ca.key')
      }));
  }

  let brokerApiCertsIncluded = false;
  if (config.brokerApiCertsDir) {
    const targetDir = path.join(bundleRoot, 'broker-api-certs');
    await fs.cp(config.brokerApiCertsDir, targetDir, {recursive: true});
    brokerApiCertsIncluded = true;
  }

  const sharedSecretSnapshot = {
    broker_admin_api: {
      secret_key_b64: config.sharedSecrets.brokerAdminApiSecretKeyB64,
      secret_key_id: config.sharedSecrets.brokerAdminApiSecretKeyId
    },
    broker_api: {
      secret_key_b64: config.sharedSecrets.brokerApiSecretKeyB64,
      secret_key_id: config.sharedSecrets.brokerApiSecretKeyId
    },
    manifest_keys_json: config.sharedSecrets.manifestKeysJson
  };
  await writeJsonFile(path.join(bundleRoot, 'service-secrets.json'), sharedSecretSnapshot);

  await writeJsonFile(path.join(bundleRoot, 'restore-context.json'), {
    backup_id: backupId,
    version,
    created_at: timestamp,
    broker_admin_certificate_issuer: config.adminCertificateIssuer,
    bundle_contents: {
      database_dump_path: databaseDumpRelativePath,
      broker_admin_local_ca_included: brokerAdminLocalCaIncluded,
      broker_api_certs_included: brokerApiCertsIncluded
    }
  });

  const tarballPath = path.join(workspaceRoot, `${backupId}.tar.gz`);
  await createTarball({sourceDir: bundleRoot, targetPath: tarballPath});
  const tarballBytes = await fs.readFile(tarballPath);

  return {
    workspaceRoot,
    bundleRoot,
    tarballPath,
    tarballBytes,
    manifestBase: {
      schema_version: 1 as const,
      backup_id: backupId,
      version,
      created_at: timestamp,
      included_artifacts: {
        database_dump_path: databaseDumpRelativePath,
        broker_admin_local_ca_included: brokerAdminLocalCaIncluded,
        broker_api_certs_included: brokerApiCertsIncluded,
        shared_secret_snapshot_included: true
      },
      external_dependencies: {
        broker_admin_certificate_issuer_mode: config.adminCertificateIssuer.mode,
        vault_addr: config.adminCertificateIssuer.vaultAddr,
        vault_pki_mount: config.adminCertificateIssuer.vaultPkiMount,
        vault_pki_role: config.adminCertificateIssuer.vaultPkiRole
      }
    }
  };
};

export const materializeEncryptedChunks = ({
  backupRootKey,
  ciphertext,
  chunkSizeBytes
}: {
  backupRootKey: string;
  ciphertext: Buffer;
  chunkSizeBytes: number;
}): BackupChunkDescriptor[] => {
  const chunks: BackupChunkDescriptor[] = [];

  for (let index = 0, offset = 0; offset < ciphertext.byteLength; index += 1, offset += chunkSizeBytes) {
    const chunk = ciphertext.subarray(offset, offset + chunkSizeBytes);
    chunks.push({
      index,
      key: `${backupRootKey}/chunks/chunk-${String(index).padStart(6, '0')}.bin`,
      size_bytes: chunk.byteLength,
      sha256: sha256Hex(chunk)
    });
  }

  return chunks;
};

export const readChunkBuffers = ({ciphertext, chunkSizeBytes}: {ciphertext: Buffer; chunkSizeBytes: number}) => {
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < ciphertext.byteLength; offset += chunkSizeBytes) {
    chunks.push(ciphertext.subarray(offset, offset + chunkSizeBytes));
  }
  return chunks;
};

export const restoreBackupBundle = async ({
  config,
  tarballPath,
  restoreRoot
}: {
  config: BackupWorkloadConfig;
  tarballPath: string;
  restoreRoot: string;
}) => {
  const unpackRoot = path.join(restoreRoot, 'bundle');
  await extractTarball({archivePath: tarballPath, targetDir: unpackRoot});

  const databaseDumpPath = path.join(unpackRoot, 'database', 'database.sql.gz');
  await restoreDatabase({
    restoreBinary: config.restoreBinary,
    databaseUrl: config.databaseUrl,
    dumpPath: databaseDumpPath
  });

  let restoredBrokerApiCerts = false;
  const brokerApiCertsSourcePath = path.join(unpackRoot, 'broker-api-certs');
  if (config.restore.brokerApiCertsDir) {
    const sourceStat = await fs.stat(brokerApiCertsSourcePath).catch(() => null);
    if (sourceStat?.isDirectory()) {
      await fs.mkdir(config.restore.brokerApiCertsDir, {recursive: true});
      await fs.cp(brokerApiCertsSourcePath, config.restore.brokerApiCertsDir, {
        recursive: true,
        force: true
      });
      restoredBrokerApiCerts = true;
    }
  }

  const brokerAdminLocalCaSourceDir = path.join(unpackRoot, 'broker-admin-local-ca');
  const brokerAdminLocalCaCertPath = path.join(brokerAdminLocalCaSourceDir, 'ca.crt');
  const brokerAdminLocalCaKeyPath = path.join(brokerAdminLocalCaSourceDir, 'ca.key');
  const restoredAdminCaCert = await copyRestoredFile({
    sourcePath: brokerAdminLocalCaCertPath,
    targetPath: config.restore.adminCaCertPath
  }).catch(() => false);
  const restoredAdminCaKey = await copyRestoredFile({
    sourcePath: brokerAdminLocalCaKeyPath,
    targetPath: config.restore.adminCaKeyPath
  }).catch(() => false);

  return {
    unpackRoot,
    serviceSecretsPath: path.join(unpackRoot, 'service-secrets.json'),
    restoredBrokerApiCerts,
    restoredAdminCaCert,
    restoredAdminCaKey
  };
};

export const createRestoreWorkspace = async ({stagingRoot, backupId}: {stagingRoot: string; backupId: string}) =>
  fs.mkdtemp(path.join(stagingRoot, `restore-${backupId}-`));

export const createTemporaryTarballPath = async ({
  workspaceRoot,
  backupId
}: {
  workspaceRoot: string;
  backupId: string;
}) => {
  const targetPath = path.join(workspaceRoot, `${backupId}.tar.gz`);
  await ensureDirectory(path.dirname(targetPath));
  return targetPath;
};

export const defaultStagingRoot = () => path.join(os.tmpdir(), 'broker-backup-workload');

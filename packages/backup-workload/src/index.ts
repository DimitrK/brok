import {promises as fs} from 'node:fs';
import {createHash} from 'node:crypto';
import path from 'node:path';

import {
  createBackupBundle,
  createRestoreWorkspace,
  createTemporaryTarballPath,
  materializeEncryptedChunks,
  readChunkBuffers,
  restoreBackupBundle,
  type BackupManifest
} from './bundle.js';
import {loadConfig} from './config.js';
import {decryptPayload, encryptPayload} from './crypto.js';
import {getObject, listManifestKeys, putObject} from './s3.js';
import {
  buildBackupId,
  buildManifestKey,
  determineNextBackupVersion,
  formatBackupTimestamp,
  parseBackupDescriptorFromManifestKey
} from './versioning.js';

const usage = () => {
  throw new Error('Usage: backup | restore [--version <backup-version-or-backup-id>]');
};

const parseRestoreVersionArg = (args: string[]) => {
  const versionFlagIndex = args.findIndex(argument => argument === '--version');
  if (versionFlagIndex === -1) {
    return undefined;
  }

  return args[versionFlagIndex + 1];
};

const sha256Hex = (value: Buffer) => createHash('sha256').update(value).digest('hex');

const uploadBackup = async () => {
  const config = loadConfig();
  await fs.mkdir(config.stagingRoot, {recursive: true});

  const manifestKeys = await listManifestKeys({
    endpoint: config.s3Endpoint,
    prefix: config.s3Prefix,
    manifestFilename: config.manifestFilename
  });
  const descriptors = manifestKeys
    .map(manifestKey =>
      parseBackupDescriptorFromManifestKey({
        manifestKey,
        prefix: config.s3Prefix
      })
    )
    .filter((value): value is NonNullable<typeof value> => value !== null);

  const version = determineNextBackupVersion(descriptors);
  const timestamp = formatBackupTimestamp(new Date());
  const backupId = buildBackupId({version, timestamp});
  const manifestKey = buildManifestKey({
    prefix: config.s3Prefix,
    backupId,
    manifestFilename: config.manifestFilename
  });
  const backupRootKey = path.posix.dirname(manifestKey);

  const bundle = await createBackupBundle({
    config,
    backupId,
    version,
    timestamp
  });

  const encryptedPayload = encryptPayload({
    plaintext: bundle.tarballBytes,
    key: config.encryptionKey
  });
  const chunkDescriptors = materializeEncryptedChunks({
    backupRootKey,
    ciphertext: encryptedPayload.ciphertext,
    chunkSizeBytes: config.chunkSizeBytes
  });
  const chunkBuffers = readChunkBuffers({
    ciphertext: encryptedPayload.ciphertext,
    chunkSizeBytes: config.chunkSizeBytes
  });

  const manifest: BackupManifest = {
    ...bundle.manifestBase,
    storage: {
      manifest_key: manifestKey,
      total_chunks: chunkDescriptors.length,
      total_bytes: encryptedPayload.ciphertext.byteLength,
      chunks: chunkDescriptors
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      iv_b64: encryptedPayload.ivB64,
      auth_tag_b64: encryptedPayload.authTagB64,
      ciphertext_sha256: encryptedPayload.sha256
    }
  };

  for (const [index, chunk] of chunkBuffers.entries()) {
    await putObject({
      endpoint: config.s3Endpoint,
      key: chunkDescriptors[index]?.key ?? usage(),
      body: chunk,
      contentType: 'application/octet-stream'
    });
  }

  await putObject({
    endpoint: config.s3Endpoint,
    key: manifestKey,
    body: `${JSON.stringify(manifest, null, 2)}\n`,
    contentType: 'application/json'
  });

  console.log(
    JSON.stringify(
      {
        status: 'ok',
        backup_id: backupId,
        version,
        manifest_key: manifestKey,
        uploaded_chunks: chunkDescriptors.length
      },
      null,
      2
    )
  );
};

const resolveRestoreManifest = async ({requestedVersion}: {requestedVersion?: string}) => {
  const config = loadConfig();
  const manifestKeys = await listManifestKeys({
    endpoint: config.s3Endpoint,
    prefix: config.s3Prefix,
    manifestFilename: config.manifestFilename
  });
  const descriptors = manifestKeys
    .map(manifestKey =>
      parseBackupDescriptorFromManifestKey({
        manifestKey,
        prefix: config.s3Prefix
      })
    )
    .filter((value): value is NonNullable<typeof value> => value !== null)
    .sort((left, right) => right.version - left.version);

  const resolvedDescriptor = requestedVersion
    ? descriptors.find(
        descriptor => descriptor.backupId === requestedVersion || String(descriptor.version) === requestedVersion
      )
    : descriptors[0];
  if (!resolvedDescriptor) {
    throw new Error(
      requestedVersion
        ? `Requested backup version ${requestedVersion} was not found under ${config.s3Prefix}`
        : `No backups found under ${config.s3Prefix}`
    );
  }

  const manifestBytes = await getObject({
    endpoint: config.s3Endpoint,
    key: resolvedDescriptor.manifestKey
  });
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as BackupManifest;
  return {config, manifest};
};

const restoreFromBackup = async ({requestedVersion}: {requestedVersion?: string}) => {
  const {config, manifest} = await resolveRestoreManifest({requestedVersion});
  if (!config.restore.confirmed) {
    throw new Error(
      'Restore requires explicit confirmation. Set BACKUP_WORKLOAD_RESTORE_CONFIRM=RESTORE before running the restore command.'
    );
  }

  const ciphertextParts: Buffer[] = [];
  for (const chunk of manifest.storage.chunks.sort((left, right) => left.index - right.index)) {
    const chunkBytes = await getObject({
      endpoint: config.s3Endpoint,
      key: chunk.key
    });
    if (chunkBytes.byteLength !== chunk.size_bytes) {
      throw new Error(
        `Chunk ${chunk.index} size mismatch: expected ${String(chunk.size_bytes)} bytes, got ${String(chunkBytes.byteLength)}`
      );
    }
    if (sha256Hex(chunkBytes) !== chunk.sha256) {
      throw new Error(`Chunk ${chunk.index} integrity check failed for ${chunk.key}`);
    }
    ciphertextParts.push(chunkBytes);
  }
  const ciphertext = Buffer.concat(ciphertextParts);
  if (ciphertext.byteLength !== manifest.storage.total_bytes) {
    throw new Error(
      `Ciphertext size mismatch: expected ${String(manifest.storage.total_bytes)} bytes, got ${String(ciphertext.byteLength)}`
    );
  }
  if (sha256Hex(ciphertext) !== manifest.encryption.ciphertext_sha256) {
    throw new Error(`Ciphertext integrity check failed for backup ${manifest.backup_id}`);
  }
  const plaintextTarball = decryptPayload({
    ciphertext,
    key: config.encryptionKey,
    ivB64: manifest.encryption.iv_b64,
    authTagB64: manifest.encryption.auth_tag_b64
  });

  await fs.mkdir(config.stagingRoot, {recursive: true});
  const restoreWorkspace = await createRestoreWorkspace({
    stagingRoot: config.stagingRoot,
    backupId: manifest.backup_id
  });
  const tarballPath = await createTemporaryTarballPath({
    workspaceRoot: restoreWorkspace,
    backupId: manifest.backup_id
  });
  await fs.writeFile(tarballPath, plaintextTarball);

  const restoreResult = await restoreBackupBundle({
    config,
    tarballPath,
    restoreRoot: restoreWorkspace
  });

  console.log(
    JSON.stringify(
      {
        status: 'ok',
        restored_backup_id: manifest.backup_id,
        restored_version: manifest.version,
        restore_workspace: restoreWorkspace,
        service_secrets_path: restoreResult.serviceSecretsPath,
        unpack_root: restoreResult.unpackRoot,
        restored_broker_api_certs: restoreResult.restoredBrokerApiCerts,
        restored_admin_ca_cert: restoreResult.restoredAdminCaCert,
        restored_admin_ca_key: restoreResult.restoredAdminCaKey
      },
      null,
      2
    )
  );
};

const main = async () => {
  const [command, ...args] = process.argv.slice(2);
  if (!command) {
    usage();
  }

  if (command === 'backup') {
    await uploadBackup();
    return;
  }

  if (command === 'restore') {
    const requestedVersion = parseRestoreVersionArg(args) ?? loadConfig().restore.version;
    await restoreFromBackup({requestedVersion});
    return;
  }

  usage();
};

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

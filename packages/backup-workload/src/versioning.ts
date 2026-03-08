export type BackupDescriptor = {
  backupId: string;
  version: number;
  timestamp: string;
  manifestKey: string;
};

const BACKUP_PREFIX_PATTERN = /^v(\d+)-(\d{8}T\d{6}Z)$/u;

export const formatBackupTimestamp = (value: Date) =>
  value
    .toISOString()
    .replace(/[-:]/gu, '')
    .replace(/\.\d{3}Z$/u, 'Z');

export const buildBackupId = ({version, timestamp}: {version: number; timestamp: string}) =>
  `v${String(version).padStart(6, '0')}-${timestamp}`;

export const buildManifestKey = ({
  prefix,
  backupId,
  manifestFilename
}: {
  prefix: string;
  backupId: string;
  manifestFilename: string;
}) => `${prefix}/${backupId}/${manifestFilename}`;

export const parseBackupDescriptorFromManifestKey = ({
  manifestKey,
  prefix
}: {
  manifestKey: string;
  prefix: string;
}): BackupDescriptor | null => {
  const normalizedPrefix = `${prefix}/`;
  if (!manifestKey.startsWith(normalizedPrefix)) {
    return null;
  }

  const relativeKey = manifestKey.slice(normalizedPrefix.length);
  const [backupId] = relativeKey.split('/', 1);
  if (!backupId) {
    return null;
  }

  const parsed = backupId.match(BACKUP_PREFIX_PATTERN);
  if (!parsed?.[1] || !parsed[2]) {
    return null;
  }

  return {
    backupId,
    version: Number.parseInt(parsed[1], 10),
    timestamp: parsed[2],
    manifestKey
  };
};

export const determineNextBackupVersion = (descriptors: BackupDescriptor[]) =>
  descriptors.reduce((maxVersion, descriptor) => Math.max(maxVersion, descriptor.version), 0) + 1;

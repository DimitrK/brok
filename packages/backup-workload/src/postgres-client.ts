import {spawn} from 'node:child_process';

export type CommandCapture = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type CommandRunner = (command: string, args: string[]) => Promise<CommandCapture>;
export type DatabaseClientCommand = {
  command: string;
  argsPrefix: string[];
  displayName: string;
};

const runCapturedCommand: CommandRunner = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', chunk => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', chunk => {
      stderr += chunk.toString();
    });

    child.on('error', reject);
    child.on('close', exitCode => {
      resolve({
        exitCode: exitCode ?? 1,
        stdout,
        stderr
      });
    });
  });

export const buildDatabaseClientCommand = ({
  binary,
  container
}: {
  binary: string;
  container?: string;
}): DatabaseClientCommand =>
  container
    ? {
        command: 'docker',
        argsPrefix: ['exec', '-i', container, binary],
        displayName: `docker exec -i ${container} ${binary}`
      }
    : {
        command: binary,
        argsPrefix: [],
        displayName: binary
      };

export const parsePostgresMajorVersion = (value: string) => {
  const match = value.match(/\b(\d+)(?:\.\d+)?\b/u);
  if (!match?.[1]) {
    return null;
  }

  return Number.parseInt(match[1], 10);
};

const detectServerMajorVersion = async ({
  databaseUrl,
  sqlClientCommand,
  run = runCapturedCommand
}: {
  databaseUrl: string;
  sqlClientCommand: DatabaseClientCommand;
  run?: CommandRunner;
}) => {
  const result = await run(sqlClientCommand.command, [
    ...sqlClientCommand.argsPrefix,
    '--dbname',
    databaseUrl,
    '-tAX',
    '-c',
    'SHOW server_version'
  ]);
  if (result.exitCode !== 0) {
    throw new Error(
      `Failed to detect PostgreSQL server version using ${sqlClientCommand.displayName}: ${result.stderr.trim() || result.stdout.trim() || `exit code ${String(result.exitCode)}`}`
    );
  }

  const majorVersion = parsePostgresMajorVersion(result.stdout);
  if (majorVersion === null) {
    throw new Error(
      `Unable to parse PostgreSQL server version from ${sqlClientCommand.displayName} output: ${result.stdout.trim()}`
    );
  }

  return majorVersion;
};

const detectDumpBinaryMajorVersion = async ({
  dumpCommand,
  run = runCapturedCommand
}: {
  dumpCommand: DatabaseClientCommand;
  run?: CommandRunner;
}) => {
  const result = await run(dumpCommand.command, [...dumpCommand.argsPrefix, '--version']);
  if (result.exitCode !== 0) {
    throw new Error(
      `Failed to inspect ${dumpCommand.displayName} version: ${result.stderr.trim() || result.stdout.trim() || `exit code ${String(result.exitCode)}`}`
    );
  }

  const combinedOutput = `${result.stdout}\n${result.stderr}`;
  const majorVersion = parsePostgresMajorVersion(combinedOutput);
  if (majorVersion === null) {
    throw new Error(`Unable to parse ${dumpCommand.displayName} version output: ${combinedOutput.trim()}`);
  }

  return majorVersion;
};

export const ensureDumpBinaryCompatibility = async ({
  databaseUrl,
  dumpCommand,
  sqlClientCommand,
  run = runCapturedCommand
}: {
  databaseUrl: string;
  dumpCommand: DatabaseClientCommand;
  sqlClientCommand: DatabaseClientCommand;
  run?: CommandRunner;
}) => {
  const [serverMajorVersion, dumpMajorVersion] = await Promise.all([
    detectServerMajorVersion({
      databaseUrl,
      sqlClientCommand,
      run
    }),
    detectDumpBinaryMajorVersion({
      dumpCommand,
      run
    })
  ]);

  if (serverMajorVersion !== dumpMajorVersion) {
    throw new Error(
      `Configured dump command '${dumpCommand.displayName}' is PostgreSQL ${String(dumpMajorVersion)}, but the target database is PostgreSQL ${String(serverMajorVersion)}. Set BACKUP_WORKLOAD_DB_DUMP_BIN to a PostgreSQL ${String(serverMajorVersion)} pg_dump binary or set BACKUP_WORKLOAD_DB_DUMP_CONTAINER to a PostgreSQL ${String(serverMajorVersion)} container before running backup.`
    );
  }
};

import {describe, expect, it} from 'vitest';

import {
  buildDatabaseClientCommand,
  ensureDumpBinaryCompatibility,
  parsePostgresMajorVersion,
  type CommandRunner
} from '../postgres-client.js';

describe('parsePostgresMajorVersion', () => {
  it('parses major versions from postgres client output', () => {
    expect(parsePostgresMajorVersion('16.12')).toBe(16);
    expect(parsePostgresMajorVersion('pg_dump (PostgreSQL) 14.2')).toBe(14);
  });
});

describe('ensureDumpBinaryCompatibility', () => {
  it('accepts matching server and pg_dump major versions', async () => {
    const run: CommandRunner = async (command, args) => {
      if (command === 'psql' && args.includes('SHOW server_version')) {
        return {exitCode: 0, stdout: '16.12\n', stderr: ''};
      }

      return {exitCode: 0, stdout: 'pg_dump (PostgreSQL) 16.3\n', stderr: ''};
    };

    await expect(
      ensureDumpBinaryCompatibility({
        databaseUrl: 'postgresql://example',
        dumpCommand: buildDatabaseClientCommand({
          binary: 'pg_dump'
        }),
        sqlClientCommand: buildDatabaseClientCommand({
          binary: 'psql'
        }),
        run
      })
    ).resolves.toBeUndefined();
  });

  it('fails with an actionable error when pg_dump major version mismatches the server', async () => {
    const run: CommandRunner = async (command, args) => {
      if (command === 'psql' && args.includes('SHOW server_version')) {
        return {exitCode: 0, stdout: '16.12\n', stderr: ''};
      }

      return {exitCode: 0, stdout: 'pg_dump (PostgreSQL) 14.2\n', stderr: ''};
    };

    await expect(
      ensureDumpBinaryCompatibility({
        databaseUrl: 'postgresql://example',
        dumpCommand: buildDatabaseClientCommand({
          binary: 'pg_dump'
        }),
        sqlClientCommand: buildDatabaseClientCommand({
          binary: 'psql'
        }),
        run
      })
    ).rejects.toThrow('Set BACKUP_WORKLOAD_DB_DUMP_BIN to a PostgreSQL 16 pg_dump binary or set BACKUP_WORKLOAD_DB_DUMP_CONTAINER');
  });

  it('builds docker exec commands for database clients when a container is configured', () => {
    expect(
      buildDatabaseClientCommand({
        binary: 'pg_dump',
        container: 'broker-postgres'
      })
    ).toEqual({
      command: 'docker',
      argsPrefix: ['exec', '-i', 'broker-postgres', 'pg_dump'],
      displayName: 'docker exec -i broker-postgres pg_dump'
    });
  });
});

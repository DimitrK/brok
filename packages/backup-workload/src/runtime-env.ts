import {existsSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const unquoteValue = (value: string) => {
  const trimmed = value.trim();
  if (trimmed.length < 2) {
    return trimmed;
  }

  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
};

export const parseDotEnv = (content: string) => {
  const parsed: Record<string, string> = {};

  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }

    const normalizedLine = line.startsWith('export ') ? line.slice('export '.length).trim() : line;
    const separatorIndex = normalizedLine.indexOf('=');
    if (separatorIndex <= 0) {
      continue;
    }

    const key = normalizedLine.slice(0, separatorIndex).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(key)) {
      continue;
    }

    parsed[key] = unquoteValue(normalizedLine.slice(separatorIndex + 1));
  }

  return parsed;
};

export const loadPackageEnv = (env: NodeJS.ProcessEnv = process.env) => {
  const externallyDefinedKeys = new Set(
    Object.entries(env)
      .filter(([, value]) => value !== undefined)
      .map(([key]) => key)
  );

  for (const filename of ['.env', '.env.local']) {
    const filePath = path.join(packageRoot, filename);
    if (!existsSync(filePath)) {
      continue;
    }

    const parsed = parseDotEnv(readFileSync(filePath, 'utf8'));
    for (const [key, value] of Object.entries(parsed)) {
      if (externallyDefinedKeys.has(key)) {
        continue;
      }

      env[key] = value;
    }
  }
};

export const initializeRuntimeEnvironment = (env: NodeJS.ProcessEnv = process.env) => {
  loadPackageEnv(env);
};

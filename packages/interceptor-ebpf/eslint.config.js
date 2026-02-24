import config from '@broker-interceptor/eslint-config';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const tsconfigRootDir = path.dirname(fileURLToPath(import.meta.url));

export default [
  ...config.node({
    project: ['./tsconfig.eslint.json'],
    tsconfigRootDir,
    packageDir: [tsconfigRootDir]
  }),
  {
    files: ['src/**/*.test.ts', 'src/**/__tests__/**'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off'
    }
  }
];

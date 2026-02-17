import config from '@broker-interceptor/eslint-config';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const tsconfigRootDir = path.dirname(fileURLToPath(import.meta.url));

export default config.react({
  project: ['./tsconfig.eslint.json'],
  tsconfigRootDir,
  packageDir: [tsconfigRootDir]
});

import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';
import security from 'eslint-plugin-security';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import jsxA11y from 'eslint-plugin-jsx-a11y';

const base = ({project, tsconfigRootDir} = {}) => {
  const packageDir = tsconfigRootDir ? [tsconfigRootDir] : undefined;
  return [
    {
      ignores: ['**/dist/**', '**/coverage/**', '**/eslint.config.js', '**/vitest.config.ts']
    },
    js.configs.recommended,
    ...tseslint.configs.recommendedTypeChecked,
    tseslint.configs.eslintRecommended,
    {
      languageOptions: {
        parserOptions: {
          project,
          tsconfigRootDir
        }
      },
      plugins: {
        import: importPlugin
      },
      rules: {
        'import/no-cycle': 'error',
        'import/no-extraneous-dependencies': [
          'error',
          {
            devDependencies: [
              '**/__tests__/**',
              '**/*.test.*',
              '**/*.spec.*',
              '**/vitest.config.*',
              '**/vitest.setup.*'
            ],
            ...(packageDir ? {packageDir} : {})
          }
        ],
        'import/order': [
          'error',
          {
            groups: [['builtin', 'external'], 'internal', ['parent', 'sibling', 'index']]
          }
        ],
        '@typescript-eslint/no-floating-promises': 'error',
        '@typescript-eslint/no-misused-promises': 'error',
        '@typescript-eslint/no-unsafe-assignment': 'error',
        '@typescript-eslint/no-unsafe-call': 'error',
        '@typescript-eslint/no-unsafe-member-access': 'error',
        '@typescript-eslint/no-unsafe-return': 'error'
      }
    }
  ];
};

const runtimeNoConsoleGuards = ({tsconfigRootDir} = {}) => {
  if (typeof tsconfigRootDir !== 'string') {
    return [];
  }

  const normalizedRoot = tsconfigRootDir.replaceAll('\\', '/');
  const isRuntimeApp =
    normalizedRoot.endsWith('/apps/broker-api') || normalizedRoot.endsWith('/apps/broker-admin-api');

  if (!isRuntimeApp) {
    return [];
  }

  return [
    {
      files: ['src/**/*.{ts,tsx,js,cjs,mjs}'],
      ignores: ['src/**/*.test.*', 'src/**/*.spec.*', 'src/**/__tests__/**'],
      rules: {
        'no-console': 'error'
      }
    }
  ];
};

const node = options => [
  ...base(options),
  {
    plugins: {
      security
    },
    rules: {
      ...security.configs.recommended.rules,
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-imports': [
        'error',
        {
          name: 'child_process',
          message: 'use a dedicated wrapper for process execution'
        }
      ],
    }
  },
  ...runtimeNoConsoleGuards(options)
];

const reactConfig = options => [
  ...base(options),
  {
    plugins: {
      react,
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y
    },
    settings: {
      react: {
        version: 'detect'
      }
    },
    rules: {
      ...react.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.configs.recommended.rules
    }
  }
];

const lintConfig = [js.configs.recommended];
lintConfig.base = base;
lintConfig.node = node;
lintConfig.react = reactConfig;

export default lintConfig;

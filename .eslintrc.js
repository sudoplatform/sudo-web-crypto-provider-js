module.exports = {
  root: true,
  overrides: [
    {
      files: ['*.js'],
      extends: 'eslint:recommended',
      parserOptions: { ecmaVersion: 2018 },
      env: { node: true },
    },
    {
      files: ['src/**/*.ts'],
      excludedFiles: ['**/*.spec.ts'],
      plugins: ['@typescript-eslint', 'import', 'tree-shaking'],
      parser: '@typescript-eslint/parser',
      parserOptions: {
        project: './tsconfig.json',
      },
      extends: ['plugin:@typescript-eslint/recommended', 'prettier'],
      rules: {
        "@typescript-eslint/no-floating-promises": "error",
        // Disallow `any`.  (This is overridden for test files, below)
        '@typescript-eslint/no-explicit-any': 'error',

        // Allow "newspaper" code structure
        '@typescript-eslint/no-use-before-define': 'off',

        // Allow property definition of prop: string = ""
        // instead of inferred type such as prop = ""
        '@typescript-eslint/no-inferrable-types': 'off',

        // Allow TS convention of ignoring args
        // https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-0.html#flag-unused-declarations-with---nounusedparameters-and---nounusedlocals
        '@typescript-eslint/no-unused-vars': [
          'error',
          { argsIgnorePattern: '^_' },
        ],

        // Soften eslint defaults so that callbacks don't need to be as verbose
        '@typescript-eslint/explicit-function-return-type': [
          'error',
          {
            allowExpressions: true,
            allowTypedFunctionExpressions: true,
          },
        ],
        'tree-shaking/no-side-effects-in-initialization': 2,
      },
    },
    {
      files: ['**/*.d.ts'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
      },
    },
    {
      files: [
        '**/*.spec.ts',
        '**/test/**/*.ts',
        'integration-tests/**/*.ts',
        'src/utils/testing/**/*.ts',
      ],
      parser: '@typescript-eslint/parser',
      parserOptions: {
        project: './tsconfig.commonjs.json',
      },
      rules: {
        "@typescript-eslint/no-floating-promises": "error",
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-non-null-assertion': 'off',
      },
    },
  ],
}

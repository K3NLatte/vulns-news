import { defineConfig } from 'eslint/config'
import js from '@eslint/js'
import ts from 'typescript-eslint'
import vue from 'eslint-plugin-vue'
import accessibility from 'eslint-plugin-vuejs-accessibility'
import globals from 'globals'

export default defineConfig([
  { ignores: ['dist/**', 'node_modules/**', 'playwright-report/**', 'test-results/**', 'coverage/**'] },
  {
    files: ['**/*.{ts,vue,mjs}'],
    extends: [js.configs.recommended, ...ts.configs.recommended, ...vue.configs['flat/essential'], ...accessibility.configs['flat/recommended']],
    rules: {
      'vuejs-accessibility/label-has-for': ['error', { required: { some: ['nesting', 'id'] } }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
      parserOptions: { parser: ts.parser },
    },
  },
  {
    files: ['src/utils/inputText.ts', 'src/utils/publicUrl.ts', 'src/services/workspace.ts', 'src/services/reports.ts', 'src/services/feedContract.ts', 'src/services/feed.ts', 'src/composables/useNavigation.ts'],
    // These boundary validators intentionally recognize forbidden control bytes.
    rules: { 'no-control-regex': 'off' },
  },
])

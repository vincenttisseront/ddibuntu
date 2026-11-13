import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  test: { include: ['tests/**/*.test.ts'], environment: 'node', testTimeout: 60000, hookTimeout: 120000, fileParallelism: false,
    coverage: { provider: 'v8', reporter: ['lcov', 'text-summary'], reportsDirectory: 'coverage', include: ['server/**/*.ts'], exclude: ['server/api/**'] } },
  resolve: { alias: { '~~': fileURLToPath(new URL('.', import.meta.url)) } },
})

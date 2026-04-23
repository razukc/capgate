import { defineConfig } from 'vitest/config';

export default defineConfig({
  cacheDir: './node_modules/.vite',
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    pool: 'threads',
    reporters: [process.env.CI ? 'dot' : 'default'],
    testTimeout: 10000,
    hookTimeout: 10000,
  },
  esbuild: {
    target: 'es2022',
  },
});

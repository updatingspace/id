import { configDefaults, defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,
  },
  test: {
    environment: 'happy-dom',
    pool: 'threads',
    globals: true,
    exclude: [...configDefaults.exclude, 'e2e/**'],
    css: true,
    server: {
      deps: {
        inline: ['@gravity-ui/uikit'],
      },
    },
    setupFiles: ['./src/setupTests.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      thresholds: {
        lines: 50,
        functions: 40,
        branches: 33,
        statements: 50,
      },
    },
  },
});

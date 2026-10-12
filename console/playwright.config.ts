import { defineConfig } from '@playwright/test';
import { randomBytes } from 'node:crypto';
export default defineConfig({
  testDir: './test',
  fullyParallel: false,
  workers: 1,
  timeout: 60000,
  use: {
    baseURL: 'http://127.0.0.1:19900',
    headless: true,
    launchOptions: {
      executablePath: process.env.CHROMIUM_PATH ?? '/usr/bin/chromium',
      args: ['--no-sandbox'],
    },
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: 'node --import tsx ../slave/test/console-server.ts',
      url: 'http://127.0.0.1:19901/readyz',
      env: { WAF_CONSOLE_TEST: 'true' },
      timeout: 60000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 15000 },
    },
    {
      command: 'npm run start -- --port 19900',
      url: 'http://127.0.0.1:19900',
      env: {
        WAF_API_URL: 'http://127.0.0.1:19901',
        CONSOLE_ORIGIN: 'http://127.0.0.1:19900',
        CONSOLE_SECURE_COOKIES: 'false',
        CONSOLE_SESSION_KEY: randomBytes(32).toString('base64'),
        NEXT_TELEMETRY_DISABLED: '1',
      },
      timeout: 30000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 },
    },
  ],
});

import { defineConfig } from '@playwright/test';
export default defineConfig({ testDir:'./tests', workers:1, timeout:20000, globalSetup:'./scripts/global-setup.mjs', use:{ browserName:'chromium' } });

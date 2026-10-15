import { defineConfig } from '@playwright/test';
export default defineConfig({ testDir:'./tests', workers:1, timeout:20000, use:{ browserName:'chromium' } });

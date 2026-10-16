import { fileURLToPath } from 'node:url';
import { startBrowserFixture } from './browser-fixture.mjs';

export default async function globalSetup() {
  const fixture = await startBrowserFixture({ root: fileURLToPath(new URL('../../../..', import.meta.url)) });
  process.env.IDENTITY_BROWSER_FIXTURE_ORIGIN = fixture.origin;
  return async () => {
    try { await fixture.close(); }
    finally { delete process.env.IDENTITY_BROWSER_FIXTURE_ORIGIN; }
  };
}

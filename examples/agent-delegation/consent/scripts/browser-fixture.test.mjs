import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import test from 'node:test';
import { startBrowserFixture } from './browser-fixture.mjs';

const node = source => [process.execPath, ['--input-type=module', '-e', source]];
const compile = () => node('');

function options(extra) {
  return { root: process.cwd(), compile, shutdownTimeout: 200, ...extra };
}

async function removed(directory) {
  await assert.rejects(access(directory), { code: 'ENOENT' });
}

test('owned fixture stops successfully and removes its unique binary directory', async () => {
  const fixture = await startBrowserFixture(options({
    launch: () => node(`import http from 'node:http';
      const server = http.createServer((req, res) => {
        if (req.method !== 'POST' || req.url !== '/fixture/stop') { res.writeHead(400).end(); return; }
        res.once('finish', () => { server.close(); server.closeAllConnections(); });
        res.writeHead(204).end();
      });
      server.listen(0, '127.0.0.1', () => console.log('BROWSER_FIXTURE_URL=http://127.0.0.1:' + server.address().port));`),
  }));
  assert.match(fixture.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  await fixture.close();
  await removed(fixture.directory);
});

test('compilation failure preserves its exit and diagnostics and removes temporary files', async () => {
  let directory;
  await assert.rejects(startBrowserFixture(options({
    compile: binary => { directory = dirname(binary); return node("console.error('synthetic compile failure'); process.exit(7)"); },
  })), /fixture compilation failed: exit 7.*synthetic compile failure/s);
  await removed(directory);
});

test('startup exit preserves its real status and removes the owned binary directory', async () => {
  let directory;
  await assert.rejects(startBrowserFixture(options({
    launch: binary => { directory = dirname(binary); return node("console.error('synthetic startup failure'); process.exit(9)"); },
  })), error => {
    const errors = error instanceof AggregateError ? error.errors : [error];
    return errors.some(e => /fixture exited before readiness: exit 9.*synthetic startup failure/s.test(e.message));
  });
  await removed(directory);
});

test('failed readiness forcibly reaps its own uncooperative child and removes files', async () => {
  let directory, pidFile, launched;
  const launchReady = new Promise(resolve => { launched = resolve; });
  const failed = assert.rejects(startBrowserFixture(options({
    readinessTimeout: 2000,
    launch: binary => {
      directory = dirname(binary);
      pidFile = binary + '.pid';
      launched();
      return node(`import { writeFileSync } from 'node:fs';
        writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
        process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);`);
    },
  })), /fixture did not become ready/);
  await launchReady;
  let pid;
  const deadline = Date.now() + 1500;
  while (!pid && Date.now() < deadline) {
    try { pid = Number(await readFile(pidFile, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (!pid) await new Promise(resolve => setTimeout(resolve, 5));
  }
  await failed;
  await removed(directory);
  assert.ok(pid > 0, 'child reached the uncooperative live state');
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
});

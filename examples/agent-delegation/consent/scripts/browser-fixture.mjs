import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const outputLimit = 32768;

function ownedProcess(command, args, options) {
  const child = spawn(command, args, { ...options, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
  const owned = { child, output: '', finished: false };
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', data => { owned.output = (owned.output + data).slice(-outputLimit); });
  }
  owned.closed = new Promise(resolve => {
    let error;
    child.once('error', err => { error = err; });
    child.once('close', (code, signal) => { owned.finished = true; resolve({ code, signal, error }); });
  });
  return owned;
}

async function bounded(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), milliseconds);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

function statusError(label, status, owned) {
  return new Error(`${label}: ${status.error?.message ?? `exit ${status.code}, signal ${status.signal}`}\n${owned.output}`);
}

async function terminate(owned, timeout) {
  for (const signal of ['SIGTERM', 'SIGKILL']) {
    if (owned.finished) return;
    try {
      if (owned.child.pid) {
        if (process.platform === 'win32') owned.child.kill(signal);
        else process.kill(-owned.child.pid, signal);
      }
    } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
    try { await bounded(owned.closed, timeout, 'fixture process did not exit'); return; }
    catch (error) { if (signal === 'SIGKILL') throw error; }
  }
}

async function ready(owned, timeout) {
  let inspect;
  try {
    return await bounded(new Promise((resolve, reject) => {
      inspect = () => {
        const match = owned.output.match(/BROWSER_FIXTURE_URL=(http:\/\/127\.0\.0\.1:\d+)/);
        if (match) resolve(match[1]);
      };
      owned.child.stdout.on('data', inspect);
      owned.closed.then(status => reject(statusError('fixture exited before readiness', status, owned)));
      inspect();
    }), timeout, 'fixture did not become ready');
  } finally {
    owned.child.stdout.off('data', inspect);
  }
}

// Compilation is outside Playwright's per-test/hook deadline. Both processes and
// their temporary files belong to this invocation, including failed setup.
export async function startBrowserFixture({ root, env = process.env, compile, launch,
  compileTimeout = 120000, readinessTimeout = 20000, shutdownTimeout = 3000 }) {
  const directory = await mkdtemp(join(tmpdir(), 'identity-agent-consent-'));
  const binary = join(directory, 'fixture.test');
  let compiler, fixture, origin;
  const cleanup = async (checkStatus = true) => {
    let failure;
    try {
      if (fixture && !fixture.finished && origin) {
        try {
          const response = await fetch(origin + '/fixture/stop', { method: 'POST', signal: AbortSignal.timeout(shutdownTimeout) });
          await response.body?.cancel();
          if (response.status !== 204) throw new Error(`fixture stop returned HTTP ${response.status}`);
          const status = await bounded(fixture.closed, shutdownTimeout, 'fixture did not stop');
          if (status.error || status.code !== 0) throw statusError('fixture shutdown failed', status, fixture);
        } catch (error) { failure = error; }
      } else if (checkStatus && fixture?.finished) {
        const status = await fixture.closed;
        if (status.error || status.code !== 0) failure = statusError('fixture failed', status, fixture);
      }
    } finally {
      try {
        if (compiler) await terminate(compiler, shutdownTimeout);
        if (fixture) await terminate(fixture, shutdownTimeout);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
    if (failure) throw failure;
  };
  try {
    const build = compile?.(binary) ?? ['go', ['test', '-c', '-o', binary, './examples/agent-delegation']];
    compiler = ownedProcess(build[0], build[1], { cwd: root, env });
    const status = await bounded(compiler.closed, compileTimeout, 'fixture compilation timed out');
    if (status.error || status.code !== 0) throw statusError('fixture compilation failed', status, compiler);
    const run = launch?.(binary) ?? [binary, ['-test.run=^TestBrowserFixture$', '-test.timeout=190s']];
    fixture = ownedProcess(run[0], run[1], { cwd: root, env: { ...env, IDENTITY_BROWSER_FIXTURE: '1' } });
    origin = await ready(fixture, readinessTimeout);
    return { origin, directory, close: cleanup };
  } catch (error) {
    try { await cleanup(false); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], `${error.message}\nCleanup: ${cleanupError.message}`); }
    throw error;
  }
}

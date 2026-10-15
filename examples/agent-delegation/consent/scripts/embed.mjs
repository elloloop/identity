import { readFile, mkdir, writeFile } from 'node:fs/promises';
const output = new URL('../../../../internal/app/ui/agent_assets/', import.meta.url);
const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
if (/<(?:script|link)[^>]+(?:src|href)=/.test(html)) throw new Error('Consent must be self-contained');
if (!html.includes('<!--IDENTITY_AGENT_CONFIG-->')) throw new Error('Missing server configuration marker');
await mkdir(output, { recursive: true });
await writeFile(new URL('consent.html', output), html);

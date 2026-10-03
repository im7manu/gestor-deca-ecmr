import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const server = resolve(root, 'server.js');
if (!existsSync(server)) {
  console.error('No se encuentra server.js');
  process.exit(1);
}
console.log('Iniciando DeCA y eCMR con Node...');
const child = spawn(process.execPath, [server], {
  cwd: root,
  stdio: 'inherit',
  env: { ...process.env, PORT: process.env.PORT || '3000' },
});
child.on('exit', code => process.exit(code ?? 0));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));

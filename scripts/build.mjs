import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('public', { recursive: true });
await copyFile('index.html', 'public/index.html');
console.log('Built public/index.html; server source and credentials excluded.');

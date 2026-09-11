import { spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, '..');
const artifactsDirectory = path.join(projectRoot, 'dist');
const stagingDirectory = await mkdtemp(path.join(os.tmpdir(), 'enhanced-network-tab-'));
const releaseFiles = [
  'manifest.json',
  'jsrepository.json',
  'LICENSE',
  'background',
  'devtools',
  'icons',
  'shared'
];

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: projectRoot,
      stdio: 'inherit'
    });
    child.once('error', reject);
    child.once('exit', code => {
      if (code === 0) resolve();
      else reject(new Error(`${command} exited with status ${code}`));
    });
  });
}

try {
  for (const relativePath of releaseFiles) {
    await cp(
      path.join(projectRoot, relativePath),
      path.join(stagingDirectory, relativePath),
      { recursive: true }
    );
  }

  await rm(path.join(stagingDirectory, '.DS_Store'), { force: true });
  await rm(path.join(stagingDirectory, 'icons', '.DS_Store'), { force: true });
  await rm(artifactsDirectory, { recursive: true, force: true });
  await mkdir(artifactsDirectory, { recursive: true });

  const executable = process.platform === 'win32'
    ? path.join(projectRoot, 'node_modules', '.bin', 'web-ext.cmd')
    : path.join(projectRoot, 'node_modules', '.bin', 'web-ext');

  await run(executable, [
    'build',
    '--source-dir', stagingDirectory,
    '--artifacts-dir', artifactsDirectory,
    '--overwrite-dest'
  ]);
} finally {
  await rm(stagingDirectory, { recursive: true, force: true });
}

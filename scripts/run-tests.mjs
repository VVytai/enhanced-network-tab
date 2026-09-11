import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, '..');
const testDirectories = [
  path.join(projectRoot, 'tests', 'unit'),
  path.join(projectRoot, 'tests', 'integration'),
];

const testFiles = [];
for (const directory of testDirectories) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') continue;
    throw error;
  }
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith('.test.js')) {
      testFiles.push(path.join(directory, entry.name));
    }
  }
}
testFiles.sort();

if (testFiles.length === 0) {
  console.log('No local automated tests found; the repository-ignored tests/ directory is optional.');
  process.exit(0);
}

const exitCode = await new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['--test', ...testFiles], {
    cwd: projectRoot,
    stdio: 'inherit',
  });
  child.once('error', reject);
  child.once('exit', (code, signal) => {
    if (signal !== null) {
      reject(new Error(`Test runner terminated by signal ${signal}.`));
      return;
    }
    resolve(code ?? 1);
  });
});

process.exitCode = exitCode;

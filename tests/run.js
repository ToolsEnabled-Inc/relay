'use strict';

// Runs every relay test in its own process.
//
// ONE PROCESS PER FILE, DELIBERATELY. These modules install and restore
// process.emitWarning (the SQLite adapter does, to silence one experimental
// warning) and open real database files. Sharing a process lets one file's
// cleanup failure be scored against the next file's assertions, which is how a
// suite starts reporting the wrong module as broken.
//
// The cross-repo test is NOT run here. It needs a checkout of the open engine
// repository beside this one, which a relay-only deployment host does not
// have. `npm run test:crossrepo` runs it explicitly. See docs/CROSS-REPO.md.

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const TESTS = path.join(__dirname);
const files = fs.readdirSync(TESTS)
  .filter(name => name.startsWith('online-fra-') && name.endsWith('.js'))
  .sort();

if (files.length === 0) {
  console.error('No relay tests found. An empty suite must never report success.');
  process.exit(2);
}

let failed = 0;
for (const name of files) {
  const started = Date.now();
  const result = spawnSync(process.execPath, [path.join(TESTS, name)], {
    encoding: 'utf8',
    windowsHide: true
  });
  const ms = Date.now() - started;
  if (result.status === 0) {
    console.log(`PASS  ${String(ms).padStart(5)}ms  ${name}`);
    continue;
  }
  failed += 1;
  console.error(`FAIL  ${String(ms).padStart(5)}ms  ${name}  (exit ${result.status})`);
  if (result.stdout) console.error(result.stdout.trimEnd());
  if (result.stderr) console.error(result.stderr.trimEnd());
}

console.log(`\n${files.length - failed}/${files.length} relay test file(s) passed.`);
process.exit(failed === 0 ? 0 : 1);

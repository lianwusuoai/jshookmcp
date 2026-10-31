#!/usr/bin/env node
/**
 * Run the tool benchmark suites and emit a scorecard.
 *
 *   corepack pnpm bench:tools
 *
 * Writes artifacts/benchmarks/scorecard.md + .json and prints the summary.
 * Exit code 1 when any suite breaches its floor — CI-friendly.
 */
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

const root = process.cwd();
const env = { ...process.env, BENCH_SCORECARD: '1' };

const res = spawnSync(
  'corepack',
  [
    'pnpm',
    'exec',
    'vitest',
    'run',
    '--project',
    'server',
    'tests/server/benchmarks/tools-benchmark.test.ts',
  ],
  { cwd: root, env, stdio: 'inherit', shell: process.platform === 'win32' },
);

const scorecardPath = resolve(root, 'artifacts/benchmarks/scorecard.md');
if (existsSync(scorecardPath)) {
  console.log('\n=== Scorecard ===\n');
  console.log(readFileSync(scorecardPath, 'utf8'));
  console.log(`Full report: ${scorecardPath}`);
}

process.exit(res.status ?? 1);

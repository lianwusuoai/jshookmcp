#!/usr/bin/env node
/**
 * Measure the e2e layer for the per-tool scorecard with REAL task runs:
 * builds the server, runs tests/e2e against the fixture site, and maps every
 * PASSED e2e test to the tools it exercises (tool names referenced in the file).
 * Writes artifacts/benchmarks/e2e-results.json — the scorecard's e2e layer input.
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { resolve, join, basename } from 'node:path';

const root = process.cwd();
const outDir = resolve(root, 'artifacts/benchmarks');
mkdirSync(outDir, { recursive: true });
const resultsFile = resolve(root, 'tests/e2e/e2e-results.json');

console.log('[bench:e2e] building + running e2e real-task tests…');
const res = spawnSync('corepack', ['pnpm', 'run', 'test:e2e'], {
  cwd: root,
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env: { ...process.env, E2E_JSON_OUT: resultsFile },
});

// A file's real tasks count as measured when ≥90% of them passed — env-gated files
// (all-skipped) stay unmeasured and honest; one flake doesn't erase a file's coverage.
if (!existsSync(resultsFile)) {
  console.error('[bench:e2e] no JSON results produced — run failed before reporting');
  process.exit(res.status ?? 1);
}
const report = JSON.parse(readFileSync(resultsFile, 'utf8'));
const fileStats = {};
for (const t of report.testResults ?? []) {
  const statuses = (t.assertionResults ?? []).map((a) => a.status);
  const passed = statuses.filter((s) => s === 'passed').length;
  const total = statuses.length;
  fileStats[basename(t.name ?? '')] = { passed, total, passRate: total ? passed / total : 0 };
}
const passedFiles = new Set(
  Object.entries(fileStats)
    .filter(([, v]) => v.passRate >= 0.9)
    .map(([f]) => f),
);
// Map each passed file to the tools it references (registry universe).
const domainsText = readFileSync(
  join(root, 'src/server/registry/generated-tool-domains.ts'),
  'utf8',
);
const allTools = [...domainsText.matchAll(/([a-z0-9_]+):\s*'/g)].map((m) => m[1]);
const e2eDir = join(root, 'tests/e2e');
const passedTools = new Set();
for (const f of passedFiles) {
  const text = readFileSync(join(e2eDir, f), 'utf8');
  for (const tool of allTools) {
    if (text.includes(`'${tool}'`) || text.includes(`"${tool}"`)) passedTools.add(tool);
  }
}
writeFileSync(
  join(outDir, 'e2e-results.json'),
  `${JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      suite: 'tests/e2e (real tasks)',
      passRateThreshold: 0.9,
      measuredFiles: [...passedFiles],
      fileStats,
      totalTests: report.numTotalTests,
      passedTests: report.numPassedTests,
      toolFileCounts: Object.fromEntries(
        [...passedTools].map((tool) => {
          let count = 0;
          for (const f of passedFiles) {
            const text = readFileSync(join(root, 'tests/e2e', f), 'utf8');
            if (text.includes(`'${tool}'`) || text.includes(`"${tool}"`)) count += 1;
          }
          return [tool, count];
        }),
      ),
    },
    null,
    2,
  )}\n`,
);
console.log(`[bench:e2e] ${passedFiles.size} passed files → ${passedTools.size} tools measured`);
process.exit(res.status ?? 0);

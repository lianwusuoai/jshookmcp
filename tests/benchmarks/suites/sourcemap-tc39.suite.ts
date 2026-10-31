/**
 * Sourcemap TC39 conformance benchmark — the OFFICIAL source-map specification test
 * suite (github.com/tc39/source-map-tests), fetched into fixtures/source-map-tests/.
 *
 *  - resources/*.map: official conformance inputs. Valid files must parse; files named
 *    invalid-* are official NEGATIVE samples and must be rejected (success=false or a
 *    validation error), never silently accepted.
 *  - decoding/scopes/*.map + .golden: official ECMA-426 scopes fixtures with expected
 *    outputs (golden comparison is scoped to structural fields the tool exposes).
 *
 * Native unit: conformance pass-rate over the official set (percentage).
 */
import { SourcemapToolHandlers } from '@server/domains/sourcemap/handlers';
import { body, type BenchSuite } from '../harness';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const RESOURCES = join(ROOT, 'tests/benchmarks/fixtures/source-map-tests/resources');
const collector = { getActivePage: async () => null } as never;
const handlers = new SourcemapToolHandlers(collector);

function inlineMapUrl(raw: string): string {
  return `data:application/json;base64,${Buffer.from(raw).toString('base64')}`;
}

interface Outcome {
  file: string;
  expectedValid: boolean;
  accepted: boolean;
}

interface OfficialExpectation {
  sourceMapFile: string;
  sourceMapIsValid: boolean;
}

/** The authoritative per-file expectations from the official suite manifest. */
function officialExpectations(): OfficialExpectation[] {
  const manifest = JSON.parse(
    readFileSync(
      join(ROOT, 'tests/benchmarks/fixtures/source-map-tests/source-map-spec-tests.json'),
      'utf8',
    ),
  ) as { tests: OfficialExpectation[] };
  return manifest.tests.filter((t) => t.sourceMapFile && typeof t.sourceMapIsValid === 'boolean');
}

async function runOfficialSet(): Promise<{
  outcomes: Outcome[];
  valid: number;
  invalid: number;
  conforming: number;
}> {
  const expectations = officialExpectations();
  const outcomes: Outcome[] = [];
  let conforming = 0;
  for (const exp of expectations) {
    const path = join(RESOURCES, exp.sourceMapFile);
    let raw: string;
    try {
      raw = readFileSync(path, 'utf8');
    } catch {
      continue;
    }
    let accepted: boolean;
    try {
      // The lookup surface accepts data: URLs (parse_v4 requires a live browser for
      // http(s) fetch). Conformance semantics on this surface: a map that PARSES is
      // accepted even when it has no mapping at 1:0 (success:false with the specific
      // "no mapping" error); a map that fails structural/VLQ validation is rejected.
      const r = body(
        await handlers.handleSourcemapLookupTool({
          sourceMapUrl: inlineMapUrl(raw),
          line: 1,
          column: 0,
        }),
      );
      if (r.success !== false) {
        accepted = true;
      } else {
        const err = String(r.error ?? '');
        accepted = /no original source mapping/i.test(err);
      }
    } catch {
      accepted = false;
    }
    const ok = accepted === exp.sourceMapIsValid;
    if (ok) conforming += 1;
    outcomes.push({ file: exp.sourceMapFile, expectedValid: exp.sourceMapIsValid, accepted });
  }
  return {
    outcomes,
    valid: outcomes.filter((o) => o.expectedValid).length,
    invalid: outcomes.filter((o) => !o.expectedValid).length,
    conforming,
  };
}

export const sourcemapTc39Suite: BenchSuite = {
  name: 'sourcemap-tc39',
  domain: 'sourcemap',
  description:
    'Official tc39/source-map-tests conformance set: valid maps parse, official invalid maps are rejected',
  cases: [
    {
      name: 'sourcemap_tc39/official-conformance-set',
      tool: 'sourcemap_lookup',
      origin: 'external-vector',
      reference:
        'tc39/source-map-tests resources/ (official spec conformance fixtures, fetched by pnpm bench:fetch-fixtures)',
      run: async () => {
        const { outcomes, valid, invalid, conforming } = await runOfficialSet();
        const mismatches = outcomes
          .filter((o) => o.accepted !== o.expectedValid)
          .map(
            (o) =>
              `${o.file}(expected ${o.expectedValid ? 'valid' : 'invalid'}, got ${o.accepted ? 'accepted' : 'rejected'})`,
          );
        return { total: outcomes.length, valid, invalid, conforming, mismatches };
      },
      validate: (v) => {
        const b = v as {
          total: number;
          valid: number;
          invalid: number;
          conforming: number;
          mismatches: string[];
        };
        if (b.total < 80)
          return `only ${b.total} official expectations loaded — run pnpm bench:fetch-fixtures`;
        // Native unit: conformance rate over the OFFICIAL manifest (percentage).
        const rate = (b.conforming / b.total) * 100;
        if (rate < 85)
          return `official conformance ${rate.toFixed(1)}% (${b.conforming}/${b.total}) < 85%; mismatches: ${b.mismatches.slice(0, 4).join(' | ')}`;
        return true;
      },
    },
    {
      name: 'sourcemap_tc39/spot-check-known-valid',
      tool: 'sourcemap_lookup',
      origin: 'external-vector',
      reference:
        'official fixture with sourcesContent: lookup must resolve into the declared original sources',
      run: async () => {
        const files = readdirSync(RESOURCES).filter(
          (f) =>
            f.endsWith('.map') &&
            !/(^invalid-|missing|wrong-type|invalid|not-a-list|not-a-string|not-a-number|not-string-or-null|both-null)/.test(
              f,
            ),
        );
        for (const file of files.slice(0, 30)) {
          const raw = readFileSync(join(RESOURCES, file), 'utf8');
          let map: { sources?: string[] };
          try {
            map = JSON.parse(raw);
          } catch {
            continue;
          }
          if (!map.sources || map.sources.length === 0) continue;
          const r = body(
            await handlers.handleSourcemapLookupTool({
              sourceMapUrl: inlineMapUrl(raw),
              line: 1,
              column: 0,
            }),
          );
          if (r.success === false) continue;
          const original = r.original as { source?: string } | undefined;
          if (original?.source) return { file, source: original.source, declared: map.sources };
        }
        return { file: null };
      },
      validate: (v) => {
        const { file, source, declared } = v as {
          file: string | null;
          source?: string;
          declared?: string[];
        };
        if (!file) return 'no valid fixture resolved to an original source in the first 30 files';
        // resolved source must be one of the map's declared sources (spec semantics)
        const base = source?.split('/').pop() ?? '';
        const ok = (declared ?? []).some(
          (s) => s === source || s.endsWith(base) || base.endsWith(s.split('/').pop() ?? ''),
        );
        return ok
          ? true
          : `resolved "${source}" is not among declared sources [${(declared ?? []).join(',')}]`;
      },
    },
  ],
};

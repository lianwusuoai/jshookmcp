/**
 * Retrieval benchmark — native retrieval metrics (MRR@10 / NDCG@10 / P@1 / P@3 /
 * P@5 / Success@3 / Success@5) for the tool-search layer, measured against the
 * repo's own search-quality eval set (103 queries with graded relevance).
 *
 * This is a REAL evaluation run: every query is executed against the live
 * ToolSearchEngine; metrics are computed with the same evaluateCase/aggregate
 * functions the search-tune optimizer uses, so the numbers are directly
 * comparable with `pnpm search:tune:report`.
 *
 * Output: artifacts/benchmarks/retrieval-metrics.{md,json} — the per-tool
 * scorecard fills its "retrieval" column (percentages, not points) from here.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Tool } from '@modelcontextprotocol/server';
import {
  buildSearchQualityFixture,
  resolveSearchQualityToolDomain,
} from '@tests/server/search/fixtures/search-quality.fixture';
import {
  aggregateSearchMetrics,
  evaluateCase,
  summarizeFailedCases,
  type RankedResult,
} from '../../../scripts/search-tune/metrics';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const state = vi.hoisted(() => ({
  allTools: [] as Tool[],
  getToolDomain: vi.fn((name: string) => resolveSearchQualityToolDomain(name)),
}));

vi.mock('@server/ToolCatalog', () => ({
  get allTools() {
    return state.allTools;
  },
  getToolDomain: state.getToolDomain,
}));

vi.mock('@src/constants', () => ({
  SEARCH_AFFINITY_BOOST_FACTOR: 0.15,
  SEARCH_AFFINITY_TOP_N: 5,
  SEARCH_DOMAIN_HUB_THRESHOLD: 3,
  SEARCH_QUERY_CACHE_CAPACITY: 500,
  SEARCH_TRIGRAM_WEIGHT: 0.12,
  SEARCH_TRIGRAM_THRESHOLD: 0.35,
  SEARCH_RRF_K: 60,
  SEARCH_RRF_RESCALE_FACTOR: 1000,
  SEARCH_RRF_BM25_BLEND: 0.5,
  SEARCH_SYNONYM_EXPANSION_LIMIT: 3,
  SEARCH_NAME_TOKEN_WEIGHT: 3,
  SEARCH_DOMAIN_TOKEN_WEIGHT: 2,
  SEARCH_DESC_TOKEN_WEIGHT: 1,
  SEARCH_PARAM_TOKEN_WEIGHT: 1.5,
  SEARCH_BM25_K1: 1.5,
  SEARCH_BM25_B: 0.75,
  SEARCH_CACHE_VECTOR_WEIGHT_TOLERANCE: 0.05,
  SEARCH_TIER_PENALTY: 0.7,
  SEARCH_RECENCY_WINDOW_MS: 0,
  SEARCH_RECENCY_MAX_BOOST: 0,
  SEARCH_EXACT_NAME_MATCH_MULTIPLIER: 2.5,
  SEARCH_DOMAIN_HUB_BOOST_MULTIPLIER: 1.08,
  SEARCH_AFFINITY_BASE_WEIGHT: 0.3,
  SEARCH_COVERAGE_PRECISION_FACTOR: 0.5,
  SEARCH_PREFIX_MATCH_MULTIPLIER: 0.5,
  SEARCH_VECTOR_ENABLED: false,
  SEARCH_VECTOR_BM25_SKIP_THRESHOLD: 12,
  SEARCH_VECTOR_MODEL_ID: 'minishlab/potion-code-16M-v2',
  SEARCH_VECTOR_PREWARM: true,
  SEARCH_VECTOR_WORKER_IDLE_MS: 0,
  SEARCH_VECTOR_RETRY_COOLDOWN_MS: 60_000,
  SEARCH_VECTOR_CACHE_ENABLED: false,
  SEARCH_VECTOR_COSINE_WEIGHT: 0.4,
  SEARCH_VECTOR_DYNAMIC_WEIGHT: false,
  SEARCH_VECTOR_LEARN_UP: 0.05,
  SEARCH_VECTOR_LEARN_DOWN: 0.03,
  SEARCH_VECTOR_LEARN_TOP_N: 5,
  SEARCH_RECENCY_TRACKER_MAX: 200,
  SEARCH_SELF_RAG_ENABLED: false,
}));

describe('retrieval benchmark (native metrics)', () => {
  beforeEach(() => {
    vi.resetModules();
    state.getToolDomain.mockClear();
    state.allTools = [...buildSearchQualityFixture().tools];
  });

  it(
    'measures MRR/NDCG/P@k/Success@k on the search-quality eval set',
    { timeout: 120_000 },
    async () => {
      const fixture = buildSearchQualityFixture();
      const { ToolSearchEngine } = await import('@server/search/ToolSearchEngineImpl');
      const engine = new ToolSearchEngine();

      const caseMetrics = [];
      const rankedByCase = new Map<string, RankedResult[]>();
      for (const testCase of fixture.cases) {
        const results = await engine.search(testCase.query, Math.max(testCase.topK, 10));
        const ranked: RankedResult[] = results.map((r) => ({
          name: r.name,
          score: Number(r.score ?? 0),
          domain: (r as { domain?: string | null }).domain ?? null,
        }));
        caseMetrics.push(evaluateCase(ranked, testCase));
        rankedByCase.set(testCase.id, ranked);
      }
      const agg = aggregateSearchMetrics(caseMetrics);

      const report = {
        generatedAt: new Date().toISOString(),
        dataset: 'search-quality fixture (tests/server/search/fixtures)',
        cases: fixture.cases.length,
        mrrAt10: agg.mrrAt10,
        ndcgAt10: agg.ndcgAt10,
        pAt1: agg.pAt1,
        pAt3: agg.pAt3,
        pAt5: agg.pAt5,
        successAt3: agg.successAt3,
        successAt5: agg.successAt5,
        objectiveScore: agg.objectiveScore,
        worstCases: summarizeFailedCases(rankedByCase, fixture.cases).slice(0, 5),
      };

      const outDir = resolve(ROOT, 'artifacts/benchmarks');
      mkdirSync(outDir, { recursive: true });
      writeFileSync(
        resolve(outDir, 'retrieval-metrics.json'),
        `${JSON.stringify(report, null, 2)}\n`,
      );
      const md = [
        '# Retrieval Benchmark (native metrics)',
        '',
        `Dataset: ${report.dataset} · ${report.cases} queries, executed live against ToolSearchEngine`,
        '',
        '| Metric | Value |',
        '|---|---:|',
        `| MRR@10 | ${(agg.mrrAt10 * 100).toFixed(1)}% |`,
        `| NDCG@10 | ${(agg.ndcgAt10 * 100).toFixed(1)}% |`,
        `| P@1 (top-1 precision) | ${(agg.pAt1 * 100).toFixed(1)}% |`,
        `| P@3 | ${(agg.pAt3 * 100).toFixed(1)}% |`,
        `| P@5 | ${(agg.pAt5 * 100).toFixed(1)}% |`,
        `| Success@3 | ${(agg.successAt3 * 100).toFixed(1)}% |`,
        `| Success@5 | ${(agg.successAt5 * 100).toFixed(1)}% |`,
        '',
        `Objective (0.45·MRR + 0.25·NDCG + 0.15·P@1 + 0.15·S@3): ${(agg.objectiveScore * 100).toFixed(1)}%`,
      ].join('\n');
      writeFileSync(resolve(outDir, 'retrieval-metrics.md'), `${md}\n`);

      // eslint-disable-next-line no-console
      console.log(
        `[retrieval] MRR@10=${(agg.mrrAt10 * 100).toFixed(1)}% NDCG@10=${(agg.ndcgAt10 * 100).toFixed(1)}% P@1=${(agg.pAt1 * 100).toFixed(1)}% S@3=${(agg.successAt3 * 100).toFixed(1)}%`,
      );

      // Gate floors — retrieval metrics are percentages; they must beat fixed floors,
      // never be restated as letter grades.
      expect(report.cases).toBeGreaterThanOrEqual(100);
      expect(agg.mrrAt10).toBeGreaterThanOrEqual(0.6);
      expect(agg.pAt1).toBeGreaterThanOrEqual(0.5);
      expect(agg.successAt3).toBeGreaterThanOrEqual(0.6);
    },
  );
});

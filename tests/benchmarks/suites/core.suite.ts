/**
 * Core / analysis domain benchmark (offline code-analysis subset).
 *
 * No public JS-deobfuscation benchmark ships offline vectors in-repo, so this suite is
 * mostly homemade fixtures in obfuscator.io style. The CATALOG maps the broader
 * webcrack/JSDeobfuscator evaluation suites for the full-tool comparison.
 *
 * Homemade fixtures:
 *  - obfuscator.io string-array + control-flow flattening sample (detection must fire;
 *    clean code must stay clean)
 *  - planted secrets / XSS sink / eval for security scan
 *  - source→sink taint path for data flow
 *  - AST matching counts
 *  - opaque predicate solving
 */
import { CoreAnalysisHandlers } from '@server/domains/analysis/handlers';
import { ObfuscationDetector } from '@server/domains/shared/modules';
import { body, expectSuccess, type BenchSuite } from '../harness';

const stubs = {
  collector: { getActivePage: async () => null, on: () => {} },
  scriptManager: {},
  deobfuscator: {},
  advancedDeobfuscator: {},
  obfuscationDetector: new ObfuscationDetector(),
  analyzer: {},
  cryptoDetector: {},
  hookManager: {},
  samplingBridge: {} as never,
  jscramblerDeobfuscator: {} as never,
} as unknown as ConstructorParameters<typeof CoreAnalysisHandlers>[0];
const handlers = new CoreAnalysisHandlers(stubs);

const OBFUSCATED_SAMPLE = `var _0x3a2b = ['log', 'hello\\x20obfuscated\\x20world'];
(function (_0x1a2b, _0x2b3c) {
  var _0x3c4d = function (_0x4e5f) {
    while (--_0x4e5f) { _0x1a2b['push'](_0x1a2b['shift']()); }
  };
  _0x3c4d(++_0x2b3c);
}(_0x3a2b, 0x1a4));
var _0x4f5a = function (_0x1, _0x2) { return _0x3a2b[_0x1 - 0x0]; };
(function () {
  var _0x5e6f = { 'xQwR': function (_0xa, _0xb) { return _0xa(_0xb); } };
  console[_0x4f5a('0x0')](_0x3a2b['1']);
}());`;

const CLEAN_SAMPLE = `function add(a, b) { return a + b; }
const result = add(1, 2);
console.log(result);`;

const SECRET_SAMPLE = `const apiKey = "AKIAIOSFODNN7EXAMPLE";
const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
fetch(url, { headers: { Authorization: "Bearer " + apiKey } });
document.getElementById('out').innerHTML = userInput;
eval(userInput);`;

const TAINT_SAMPLE = `const params = new URLSearchParams(window.location.search);
const q = params.get('q');
document.getElementById('out').innerHTML = q;`;

const OPAQUE_PREDICATE_SAMPLE = `function secret() { return 42; }
if (0x1514 * 0x1 + 0x9 > 0x1514) {
  // opaque: always true
  secret();
}
while (true) { break; }`;

export const coreSuite: BenchSuite = {
  name: 'core-analysis',
  domain: 'core',
  description:
    'obfuscation detection, security scan, data-flow taint, AST matching, opaque predicate solving (homemade obfuscator.io-style fixtures)',
  cases: [
    {
      name: 'detect_obfuscation/flags-string-array-sample',
      tool: 'detect_obfuscation',
      origin: 'homemade',
      reference:
        'obfuscator.io-style string-array + hex identifiers + IIFE rotation — must detect ≥1 technique type',
      run: () => handlers.handleDetectObfuscation({ code: OBFUSCATED_SAMPLE }),
      validate: (v) => {
        const b = body(v);
        const types = (b.types ?? []) as string[];
        if (Array.isArray(types) && types.length > 0) return true;
        const text = JSON.stringify(b).toLowerCase();
        if (/confidence":\s*0\.|obfuscat/i.test(text) && !/"types":\[\]/.test(text)) return true;
        return `no technique detected in obfuscated sample: ${text.slice(0, 260)}`;
      },
    },
    {
      name: 'detect_obfuscation/clean-code-stays-clean',
      tool: 'detect_obfuscation',
      origin: 'homemade',
      reference:
        'plain readable code must not be flagged as obfuscated — only the "unknown" placeholder type at low confidence is allowed',
      run: () => handlers.handleDetectObfuscation({ code: CLEAN_SAMPLE }),
      validate: (v) => {
        const b = body(v);
        const types = (b.types ?? []) as string[];
        const realTypes = Array.isArray(types) ? types.filter((t) => t !== 'unknown') : [];
        if (realTypes.length === 0) return true;
        const confidence = (b.confidence ?? {}) as Record<string, number>;
        const maxReal = Math.max(...realTypes.map((t) => confidence[t] ?? 0));
        return maxReal < 0.6 ? true : `clean code flagged as ${realTypes.join(',')} at ${maxReal}`;
      },
    },
    {
      name: 'analysis_security_scan/planted-risks',
      tool: 'analysis_security_scan',
      origin: 'homemade',
      reference:
        'planted risks: AWS key id, GitHub token, document.write + eval sinks — each must be reported',
      run: () => handlers.handleAnalysisSecurityScan({ code: SECRET_SAMPLE }),
      validate: (v) => {
        const b = expectSuccess(v);
        const risks = (b.risks ?? []) as Array<{ type?: string; severity?: string }>;
        if (!Array.isArray(risks) || risks.length === 0) return 'no risks reported';
        const text = JSON.stringify(risks).toLowerCase();
        const problems: string[] = [];
        if (!text.includes('eval')) problems.push('eval sink missed');
        if (
          !text.includes('document.write') &&
          !text.includes('documentwrite') &&
          !text.includes('xss')
        )
          problems.push('XSS/document.write sink missed');
        if (!text.includes('key') && !text.includes('secret') && !text.includes('token'))
          problems.push('hardcoded secret missed');
        return problems.length === 0 ? true : problems.join('; ');
      },
    },
    {
      name: 'analysis_data_flow/taint-source-to-sink',
      tool: 'analysis_data_flow',
      origin: 'homemade',
      reference:
        'taint contract: URLSearchParams source → innerHTML sink must produce a tainted path',
      run: () => handlers.handleAnalysisDataFlow({ code: TAINT_SAMPLE }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const text = JSON.stringify(b).toLowerCase();
        if (!text.includes('innerhtml')) return 'innerHTML sink not found';
        if (!text.includes('source') || !text.includes('sink'))
          return `no source/sink structure: ${text.slice(0, 240)}`;
        return true;
      },
    },
    {
      name: 'analysis_ast_match/call-expression-count',
      tool: 'analysis_ast_match',
      origin: 'homemade',
      reference:
        'AST matching: CLEAN_SAMPLE has exactly 2 CallExpressions (add(1,2) and console.log(result))',
      run: () =>
        handlers.handleAnalysisAstMatch({
          code: CLEAN_SAMPLE,
          nodeType: 'CallExpression',
        }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const text = JSON.stringify(b);
        const m = text.match(/"(matches|count|total)":\s*(\d+)/);
        if (!m) return `no match count in response: ${text.slice(0, 240)}`;
        const count = Number(m[2]);
        return count === 2 ? true : `expected 2 CallExpressions, got ${count}`;
      },
    },
    {
      name: 'js_solve_constraints/opaque-predicate',
      tool: 'js_solve_constraints',
      origin: 'homemade',
      reference:
        'opaque predicate `0x1514 + 9 > 0x1514` is statically true — solver must mark it solved/true',
      run: () => handlers.handleJsSolveConstraints({ code: OPAQUE_PREDICATE_SAMPLE }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const text = JSON.stringify(b).toLowerCase();
        if (/solved|simplified|constant|true/.test(text)) return true;
        return `no solved marker: ${text.slice(0, 240)}`;
      },
    },
  ],
};

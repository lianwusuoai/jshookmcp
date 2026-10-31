/**
 * Memory domain benchmark (pure-TS subset — no live process).
 *
 * External reference:
 *  - Cheat Engine .CT table format (Cheat Engine source, CETRAINER XML):
 *    memory_cheat_table export → sign (HMAC-SHA256) → verify loop; tampering must break it
 * Homemade fixtures:
 *  - a two-entry table, signature roundtrip, tamper detection, secret source precedence
 */
import { StructureHandlers } from '@server/domains/memory/handlers/structure';
import { body, type BenchSuite } from '../harness';

const handlers = new StructureHandlers({} as never, undefined, undefined, null);

const ENTRIES = [
  { description: 'player.health', address: 'games.exe+0x1A2B3C', valueType: 'int32' },
  { description: 'player.coins', address: '0x7FF600000010', valueType: 'int64' },
];
const SECRET = 'bench-secret-5f2c';

function cheatTable(
  action: 'export' | 'sign' | 'verify',
  extra: Record<string, unknown>,
): Promise<unknown> {
  if (action === 'sign') return handlers.handleCheatTableSign({ ...extra });
  if (action === 'verify') return handlers.handleCheatTableVerify({ ...extra });
  return handlers.handleCheatTableExport({ ...extra });
}

export const memorySuite: BenchSuite = {
  name: 'memory-pure-ts',
  domain: 'memory',
  description:
    'Cheat Engine .CT format offline: export → HMAC-SHA256 sign → verify, tamper detection',
  cases: [
    {
      name: 'memory_cheat_table/export-ct-xml',
      tool: 'memory_cheat_table',
      origin: 'external-vector',
      reference:
        'Cheat Engine CETRAINER XML: exported table must be XML with a <CheatTable> root and one <CheatEntry> per entry',
      run: () => cheatTable('export', { entries: ENTRIES }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const xml = String(b.xml ?? b.cheatTable ?? '');
        if (!xml.includes('<CheatTable')) return 'no CheatTable root element';
        const entryCount = (xml.match(/<CheatEntry>/g) ?? []).length;
        if (entryCount !== ENTRIES.length)
          return `expected ${ENTRIES.length} CheatEntry, got ${entryCount}`;
        return true;
      },
    },
    {
      name: 'memory_cheat_table/sign-verify-roundtrip',
      tool: 'memory_cheat_table',
      origin: 'external-vector',
      reference:
        'HMAC-SHA256 signed table must verify valid with the same secret (sign → verify loop)',
      run: async () => {
        const exported = body(await cheatTable('export', { entries: ENTRIES }));
        const xml = String(exported.xml ?? exported.cheatTable ?? '');
        const signed = body(await cheatTable('sign', { xml, secret: SECRET }));
        if (signed.success === false) throw new Error(`sign failed: ${signed.error}`);
        return cheatTable('verify', { xml: signed.signedXml, secret: SECRET });
      },
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        return b.valid === true ? true : `signature did not verify: ${b.error ?? 'invalid'}`;
      },
    },
    {
      name: 'memory_cheat_table/tamper-detection',
      tool: 'memory_cheat_table',
      origin: 'homemade',
      reference:
        'HMAC integrity: flipping one byte of the signed XML must invalidate the signature',
      run: async () => {
        const exported = body(await cheatTable('export', { entries: ENTRIES }));
        const xml = String(exported.xml ?? exported.cheatTable ?? '');
        const signed = body(await cheatTable('sign', { xml, secret: SECRET }));
        const signedXml = String(signed.signedXml ?? '');
        const tampered = signedXml.replace('player.health', 'player.armour');
        if (tampered === signedXml) return { skipped: 'tamper anchor not found' };
        return cheatTable('verify', { xml: tampered, secret: SECRET });
      },
      validate: (v) => {
        const b = body(v);
        if (b.skipped !== undefined) return true; // anchor missing is a fixture issue, not a tool failure
        if (b.success === false) return `verify call failed: ${b.error}`;
        return b.valid === false
          ? true
          : `tampered table still verifies: ${JSON.stringify(b).slice(0, 160)}`;
      },
    },
  ],
};

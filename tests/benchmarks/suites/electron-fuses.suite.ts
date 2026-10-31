/**
 * Electron fuses benchmark (platform domain, offline subset).
 *
 * External vector (official Electron fuse wire format — electronjs.org/docs fuses):
 *   sentinel "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" + 1B fuse_version + 1B fuse_wire_length
 *   + fuse bytes (0x00 = disabled, 0x01 = enabled, 0x30 "removed").
 */
import { PlatformToolHandlers } from '@server/domains/platform/handlers';
import { body, expectSuccess, type BenchSuite } from '../harness';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const collector = { getActivePage: async () => null } as never;
const handlers = new PlatformToolHandlers(collector);

const tmp = mkdtempSync(join(tmpdir(), 'jshook-bench-fuses-'));
process.once('exit', () => {
  try {
    require('node:fs').rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* tmpdir */
  }
});

// Official fuse wire: sentinel + version 1 + wire length 6 + six fuse bytes
const FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii');
// @electron/fuses v2 wire: state bytes are ASCII '0' (disable), '1' (enable), 'r' (removed)
const DISABLE = 0x30;
const ENABLE = 0x31;
function fuseBinary(states: number[]): Buffer {
  const filler = Buffer.alloc(64, 0x90); // pretend .text padding
  const version = Buffer.from([1]);
  const length = Buffer.from([states.length]);
  const wire = Buffer.from(states);
  return Buffer.concat([filler, FUSE_SENTINEL, version, length, wire, Buffer.alloc(32, 0)]);
}
// run_as_node=disable, cookie_encryption=enable, node_options=disable, node_cli=disable,
// embedded_asar_integrity=enable, only_load_app_from_asar=disable — hardened Electron wire
const fusedPath = join(tmp, 'electron-hardened');
writeFileSync(fusedPath, fuseBinary([DISABLE, ENABLE, DISABLE, DISABLE, ENABLE, DISABLE]));
const unfusedPath = join(tmp, 'electron-stock');
writeFileSync(unfusedPath, fuseBinary([ENABLE, DISABLE, ENABLE, ENABLE, DISABLE, ENABLE]));

export const electronFusesSuite: BenchSuite = {
  name: 'electron-fuses',
  domain: 'platform',
  description: 'Official Electron fuse wire format: sentinel location, version, per-fuse states',
  cases: [
    {
      name: 'electron_check_fuses/official-wire-format',
      tool: 'electron_check_fuses',
      origin: 'external-vector',
      reference:
        'electronjs.org fuses spec: sentinel dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX + version byte + length byte + states (0/1)',
      run: () => handlers.handleElectronCheckFusesTool({ exePath: fusedPath }),
      validate: (v) => {
        const b = expectSuccess(v);
        const text = JSON.stringify(b).toLowerCase();
        if (!text.includes('runasnode') && !text.includes('run_as_node'))
          return 'run_as_node fuse not reported';
        // hardened wire: run_as_node disabled (0), cookie encryption enabled (1)
        if (!/run_?as_?node["']?\s*:\s*["']?(disable|false|0)/i.test(text))
          return `run_as_node should read disabled, got: ${text.slice(0, 240)}`;
        return true;
      },
    },
    {
      name: 'electron_check_fuses/distinguishes-wires',
      tool: 'electron_check_fuses',
      origin: 'homemade',
      reference: 'two different official-format wires must produce different fuse states',
      run: async () => {
        const hardened = body(await handlers.handleElectronCheckFusesTool({ exePath: fusedPath }));
        const stock = body(await handlers.handleElectronCheckFusesTool({ exePath: unfusedPath }));
        return { hardened: JSON.stringify(hardened), stock: JSON.stringify(stock) };
      },
      validate: (v) => {
        const { hardened, stock } = v as { hardened: string; stock: string };
        return hardened !== stock ? true : 'different fuse wires produced identical reports';
      },
    },
  ],
};

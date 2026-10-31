/**
 * Binary-instrument domain benchmark (pure-compute subset — no frida/jadx/ghidra).
 *
 * External references:
 *  - DEX file magic "dex\n035\0" (Android ART dex_file_struct.h)
 *  - Shannon entropy classification rule shipped in the tool's own contract:
 *    ≥7.0 bits/byte = encrypted/compressed, <4.0 = code/text
 * Homemade fixtures:
 *  - binary with a constant region and a uniform-random region: profile must separate them
 *  - strings extraction over ASCII + UTF-16LE
 *  - packer signature matching against a caller-supplied custom signature table
 */
import { BinaryScanHandlers } from '@server/domains/binary-instrument/handlers/binary-scan';
import { ApkPackerHandlers } from '@server/domains/binary-instrument/apk-packer/handlers.impl';
import { body, type BenchSuite } from '../harness';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const scan = new BinaryScanHandlers();
const apk = new ApkPackerHandlers();

const tmp = mkdtempSync(join(tmpdir(), 'jshook-bench-bin-'));

// Fixture 1: constant 4KiB region + 4KiB random region
const constRegion = Buffer.alloc(4096, 0x41);
const randRegion = randomBytes(4096);
const mixedBinary = Buffer.concat([constRegion, randRegion]);
const mixedPath = join(tmp, 'mixed.bin');
writeFileSync(mixedPath, mixedBinary);

// Fixture 2: strings — UTF-16LE payload starts at an even byte offset so its
// 2-byte alignment is detectable (odd-offset UTF-16 is a known tool gap).
const asciiStr = 'libnative_sign_payload'; // 22 bytes at offset 2 → ends at 24
const stringsBinary = Buffer.concat([
  Buffer.from([0x00, 0x00]),
  Buffer.from(asciiStr, 'ascii'),
  Buffer.from([0x00, 0x00]), // offsets 24-25
  Buffer.from('SecretKeyStore', 'utf16le'), // starts at even offset 26
  Buffer.from([0x00, 0x00]),
]);
const stringsPath = join(tmp, 'strings.bin');
writeFileSync(stringsPath, stringsBinary);

// Fixture 2b: UTF-16LE string starting at an ODD byte offset (preceded by an
// odd-length ASCII string + terminator) — regression case for the phase scan.
const oddStringsBinary = Buffer.concat([
  Buffer.from([0x00]),
  Buffer.from('abcde', 'ascii'), // offsets 1-5 (odd length shifts the terminator)
  Buffer.from([0x00]), // offset 6
  Buffer.from('OddKey', 'utf16le'), // starts at ODD offset 7
  Buffer.from([0x00, 0x00]),
]);
const oddStringsPath = join(tmp, 'strings-odd.bin');
writeFileSync(oddStringsPath, oddStringsBinary);

// Fixture 3: DEX magic
const dexBinary = Buffer.concat([Buffer.from('dex\n035\0', 'ascii'), Buffer.alloc(32, 0)]);
const dexPath = join(tmp, 'classes.dex');
writeFileSync(dexPath, dexBinary);

// Fixture 4: unpacked "APK" directory with a packer-named .so (dirPath mode)
const fakeApkDir = join(tmp, 'packed-apk');
mkdirSync(join(fakeApkDir, 'lib', 'arm64-v8a'), { recursive: true });
writeFileSync(join(fakeApkDir, 'lib', 'arm64-v8a', 'libjiagu.so'), Buffer.from('fake elf'));
writeFileSync(join(fakeApkDir, 'lib', 'arm64-v8a', 'libnative.so'), Buffer.from('fake elf'));

const cleanup = () => rmSync(tmp, { recursive: true, force: true });
process.once('exit', cleanup);

export const binarySuite: BenchSuite = {
  name: 'binary-instrument',
  domain: 'binary-instrument',
  description:
    'entropy profile separation, strings extraction (ASCII/UTF-16LE), DEX magic scan, packer signature detection',
  cases: [
    {
      name: 'binary_entropy_profile/regions-separated',
      tool: 'binary_entropy_profile',
      origin: 'homemade',
      reference:
        'tool contract: ≥7.0 bits/byte flags encrypted/compressed — stats must span [0 (constant region), ≥7 (random region)] and flag high regions at offset ≥4096',
      run: () => scan.handleBinaryEntropyProfile({ filePath: mixedPath }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const stats = b.stats as { minEntropy?: number; maxEntropy?: number } | undefined;
        if (!stats || typeof stats.minEntropy !== 'number' || typeof stats.maxEntropy !== 'number')
          return `no stats block: ${JSON.stringify(b).slice(0, 240)}`;
        if (stats.minEntropy > 1.0)
          return `constant region not low entropy: min=${stats.minEntropy}`;
        if (stats.maxEntropy < 7.0)
          return `random region not high entropy: max=${stats.maxEntropy}`;
        const regions = (b.highEntropyRegions ?? []) as Array<{ offset?: number }>;
        if (!Array.isArray(regions) || regions.length === 0)
          return 'no high-entropy regions flagged';
        if (regions.some((r) => (r.offset ?? Infinity) < 4096))
          return 'constant region incorrectly flagged as high entropy';
        return true;
      },
    },
    {
      name: 'binary_strings_extract/ascii-and-utf16',
      tool: 'binary_strings_extract',
      origin: 'homemade',
      reference:
        'planted strings: ASCII "libnative_sign_payload" and 16-bit-aligned UTF-16LE "SecretKeyStore"',
      run: () => scan.handleBinaryStringsExtract({ filePath: stringsPath }),
      validate: (v) => {
        const b = body(v);
        const text = JSON.stringify(b);
        if (b.success === false) return `failed: ${b.error}`;
        if (!text.includes('libnative_sign_payload')) return 'ASCII string missed';
        if (!text.includes('SecretKeyStore')) return 'UTF-16LE string missed (aligned case)';
        return true;
      },
    },
    {
      name: 'binary_strings_extract/utf16-odd-offset',
      tool: 'binary_strings_extract',
      origin: 'homemade',
      reference:
        'UTF-16LE "OddKey" starting at byte offset 7 (odd phase after an odd-length ASCII run) must be found',
      run: () => scan.handleBinaryStringsExtract({ filePath: oddStringsPath }),
      validate: (v) => {
        const b = body(v);
        const text = JSON.stringify(b);
        if (b.success === false) return `failed: ${b.error}`;
        if (!text.includes('OddKey')) return 'odd-offset UTF-16LE string missed';
        return true;
      },
    },
    {
      name: 'binary_strings_extract/regex-filter',
      tool: 'binary_strings_extract',
      origin: 'homemade',
      reference: 'regex filter (pattern arg) must keep only matching strings',
      run: () =>
        scan.handleBinaryStringsExtract({
          filePath: stringsPath,
          pattern: 'libnative_.*',
        }),
      validate: (v) => {
        const b = body(v);
        const text = JSON.stringify(b);
        if (!text.includes('libnative_sign_payload')) return 'matching string missed';
        if (text.includes('SecretKeyStore')) return 'non-matching string leaked through filter';
        return true;
      },
    },
    {
      name: 'dex_scan_file/dex-magic',
      tool: 'dex_scan_file',
      origin: 'external-vector',
      reference: 'DEX magic "dex\n035\0" (ART dex_file_struct.h) must be detected at offset 0',
      run: () => scan.handleDexScanFile({ filePath: dexPath }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const text = JSON.stringify(b).toLowerCase();
        if (!text.includes('dex')) return 'dex not reported';
        const hits = (b.hits ?? b.matches ?? b.found) as
          | Array<{ offset?: number }>
          | boolean
          | undefined;
        if (typeof hits === 'boolean') return hits ? true : 'dex magic not found';
        if (Array.isArray(hits)) {
          if (hits.length === 0) return 'no hits for a file that IS a dex';
          if (hits[0]?.offset !== undefined && hits[0].offset !== 0)
            return `expected offset 0, got ${hits[0].offset}`;
        }
        return true;
      },
    },
    {
      name: 'apk_packer_detect/custom-signature-match',
      tool: 'apk_packer_detect',
      origin: 'homemade',
      reference:
        'caller-supplied signature table: a lib/arm64-v8a/libjiagu.so file must match a custom jiagu-style signature (dirPath mode)',
      run: () =>
        apk.handleApkPackerDetect({
          dirPath: fakeApkDir,
          customSignatures: [
            {
              name: 'custom-jiagu-test',
              category: 'packer',
              libPatterns: ['libjiagu.*\\.so'],
            },
          ],
        }),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const text = JSON.stringify(b).toLowerCase();
        if (!text.includes('custom-jiagu-test') && !text.includes('jiagu'))
          return `custom signature did not match: ${text.slice(0, 260)}`;
        return true;
      },
    },
    {
      name: 'apk_packer_list_signatures/empty-default',
      tool: 'apk_packer_list_signatures',
      origin: 'homemade',
      reference:
        'framework ships NO built-in signature table (documented contract) — default is empty',
      run: () => apk.handleApkPackerListSignatures({}),
      validate: (v) => {
        const b = body(v);
        if (b.success === false) return `failed: ${b.error}`;
        const sigs = (b.signatures ?? b.list ?? b.items) as unknown[] | undefined;
        if (Array.isArray(sigs) && sigs.length > 0)
          return `expected empty default table, got ${sigs.length} entries`;
        return true;
      },
    },
  ],
};

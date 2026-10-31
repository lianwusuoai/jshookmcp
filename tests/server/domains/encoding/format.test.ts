import { describe, it, expect } from 'vitest';
import {
  decodeBase64String,
  decodeBinaryAuto,
  decodeHexString,
  decodeUrl,
  encodeUrlBytes,
  hexDump,
  isMostlyPrintableText,
  looksLikeBase64,
  looksLikeHex,
  looksLikeUrlEncoded,
  previewHex,
  toSafeUtf8,
  tryParseJson,
} from '@server/domains/encoding/handlers/shared';

describe('encoding shared (format utilities)', () => {
  describe('isMostlyPrintableText', () => {
    it('returns true for empty string', async () => {
      expect(isMostlyPrintableText('')).toBe(true);
    });

    it('returns true for all printable ASCII text', async () => {
      expect(isMostlyPrintableText('Hello, world!')).toBe(true);
    });

    it('treats tab/newline/carriage-return as printable', async () => {
      expect(isMostlyPrintableText('line1\nline2\tend\r')).toBe(true);
    });

    it('returns false when printable ratio is below 85%', async () => {
      const text = 'A'.repeat(16) + '\u0000'.repeat(4); // 16/20 = 0.8
      expect(isMostlyPrintableText(text)).toBe(false);
    });

    it('returns true exactly at the 85% boundary', async () => {
      const text = 'A'.repeat(17) + '\u0000'.repeat(3); // 17/20 = 0.85
      expect(isMostlyPrintableText(text)).toBe(true);
    });

    it('does not count non-ASCII unicode as printable', async () => {
      expect(isMostlyPrintableText('你好')).toBe(false);
    });
  });

  describe('previewHex', () => {
    it('returns empty string for empty buffer', async () => {
      expect(previewHex(Buffer.alloc(0), 16)).toBe('');
    });

    it('returns empty string when maxBytes is 0', async () => {
      expect(previewHex(Buffer.from([0x00, 0x01]), 0)).toBe('');
    });

    it('formats short buffer as two-digit lowercase hex bytes separated by spaces', async () => {
      expect(previewHex(Buffer.from([0x00, 0x01, 0xff]), 10)).toBe('00 01 ff');
    });

    it('truncates output at maxBytes', async () => {
      expect(previewHex(Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04]), 3)).toBe('00 01 02');
    });

    it('does not add extra spaces for a single byte', async () => {
      expect(previewHex(Buffer.from([0xab]), 1)).toBe('ab');
    });
  });

  describe('hexDump', () => {
    it('returns empty string for empty buffer', async () => {
      expect(hexDump(Buffer.alloc(0))).toBe('');
    });

    it('dumps a single 16-byte row with correct offset, hex, and ASCII columns', async () => {
      const buffer = Buffer.from('0123456789abcdef', 'ascii');
      const expected =
        '00000000  30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66  |0123456789abcdef|';
      expect(hexDump(buffer)).toBe(expected);
    });

    it("renders non-printable bytes as '.' in ASCII column", async () => {
      const buffer = Buffer.from([0x41, 0x00, 0x42, 0x7f, 0x20, 0xff]);
      const dump = hexDump(buffer);
      expect(dump).toMatch(/^00000000  41 00 42 7f 20 ff\s+\|A\.B\. \.\|$/);
    });

    it('produces multiple rows when buffer exceeds bytesPerRow', async () => {
      const buffer = Buffer.from(Array.from({ length: 20 }, (_, i) => i));
      const dump = hexDump(buffer);
      const lines = dump.split('\n');
      expect(lines).toHaveLength(2);
      expect(lines[0]).toContain('00000000');
      expect(lines[0]).toContain('|................|');
      expect(lines[1]).toContain('00000010');
      expect(lines[1]).toContain('|....|');
    });

    it('supports custom bytesPerRow', async () => {
      const buffer = Buffer.from(Array.from({ length: 9 }, (_, i) => i));
      const dump = hexDump(buffer, 8);
      const lines = dump.split('\n');
      expect(lines).toHaveLength(2);
      expect(lines[0]).toContain('00000000');
      expect(lines[1]).toContain('00000008');
    });

    it('uses lowercase hex in the hex column', async () => {
      const dump = hexDump(Buffer.from([0xab]));
      expect(dump).toContain('ab');
    });

    it('pads the hex column for short rows before the ASCII column', async () => {
      const dump = hexDump(Buffer.from('Hi', 'ascii'));
      expect(dump).toMatch(/00000000  48 69\s{2,}\|Hi\|$/);
    });

    it('does not end with a trailing newline', async () => {
      const buffer = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
      const dump = hexDump(buffer);
      expect(dump.endsWith('\n')).toBe(false);
    });
  });

  describe('decodeHexString', () => {
    it('decodes a plain hex string', async () => {
      expect(decodeHexString('deadbeef')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('decodes uppercase hex string', async () => {
      expect(decodeHexString('DEADBEEF')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('decodes hex with 0x prefix', async () => {
      expect(decodeHexString('0xdeadbeef')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('decodes hex with 0X prefix and embedded spaces', async () => {
      expect(decodeHexString('0XDE AD BE EF')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('decodes colon-separated hex', async () => {
      expect(decodeHexString('de:ad:be:ef')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('decodes hex with mixed separators (spaces, hyphens, commas)', async () => {
      expect(decodeHexString('de-ad be,ef')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('returns empty buffer for empty string', async () => {
      expect(decodeHexString('')).toEqual(Buffer.alloc(0));
    });

    it('returns empty buffer for whitespace-only string', async () => {
      expect(decodeHexString('   \n\t  ')).toEqual(Buffer.alloc(0));
    });

    it('returns empty buffer for only 0x prefix', async () => {
      expect(decodeHexString('0x')).toEqual(Buffer.alloc(0));
    });

    it('throws on odd-length hex', async () => {
      expect(() => decodeHexString('abc')).toThrow('Invalid hex string');
    });

    it('throws on non-hex characters', async () => {
      expect(() => decodeHexString('0x0g')).toThrow('Invalid hex string');
    });

    it('throws when separators are not recognized (e.g., underscore)', async () => {
      expect(() => decodeHexString('aabb__ccdd')).toThrow('Invalid hex string');
    });
  });

  describe('decodeBase64String', () => {
    it('decodes valid base64', async () => {
      expect(decodeBase64String('aGVsbG8=')).toEqual(Buffer.from('hello', 'utf8'));
    });

    it('decodes base64 containing spaces', async () => {
      expect(decodeBase64String('aGVs bG8=')).toEqual(Buffer.from('hello', 'utf8'));
    });

    it('decodes base64 containing newlines and tabs', async () => {
      expect(decodeBase64String('aGVs\n\tbG8=')).toEqual(Buffer.from('hello', 'utf8'));
    });

    it('returns empty buffer for empty string', async () => {
      expect(decodeBase64String('')).toEqual(Buffer.alloc(0));
    });

    it('returns empty buffer for whitespace-only string', async () => {
      expect(decodeBase64String('   \n\t  ')).toEqual(Buffer.alloc(0));
    });

    it('throws on invalid characters', async () => {
      expect(() => decodeBase64String('aGVsbG8$')).toThrow('Invalid base64 string');
    });

    it('throws when length is not a multiple of 4', async () => {
      expect(() => decodeBase64String('aGVsbG8')).toThrow('Invalid base64 string');
    });

    it('throws on non-canonical base64 (roundtrip mismatch)', async () => {
      expect(() => decodeBase64String('Zm9=')).toThrow('Invalid base64 string');
    });

    it('throws on base64url-like alphabet characters', async () => {
      expect(() => decodeBase64String('-w==')).toThrow('Invalid base64 string');
      expect(() => decodeBase64String('_w==')).toThrow('Invalid base64 string');
    });
  });

  describe('decodeBinaryAuto', () => {
    it('returns empty buffer for empty string', async () => {
      expect(decodeBinaryAuto('')).toEqual(Buffer.alloc(0));
    });

    it('returns empty buffer for whitespace-only string', async () => {
      expect(decodeBinaryAuto('   \n\t  ')).toEqual(Buffer.alloc(0));
    });

    it('auto-detects hex (0x prefix)', async () => {
      expect(decodeBinaryAuto('0x666f6f')).toEqual(Buffer.from('foo', 'utf8'));
    });

    it('auto-detects hex with separators', async () => {
      expect(decodeBinaryAuto('66 6f 6f')).toEqual(Buffer.from('foo', 'utf8'));
    });

    it('auto-detects base64', async () => {
      expect(decodeBinaryAuto('Zm9v')).toEqual(Buffer.from('foo', 'utf8'));
    });

    it('auto-detects base64 with whitespace', async () => {
      expect(decodeBinaryAuto('Zm 9v')).toEqual(Buffer.from('foo', 'utf8'));
    });

    it('falls back to utf8 for plain strings', async () => {
      expect(decodeBinaryAuto('hello')).toEqual(Buffer.from('hello', 'utf8'));
    });

    it('trims input before utf8 fallback', async () => {
      expect(decodeBinaryAuto('  hello  ')).toEqual(Buffer.from('hello', 'utf8'));
    });

    it('prefers hex over base64 when both could match', async () => {
      expect(decodeBinaryAuto('deadbeef')).toEqual(Buffer.from('deadbeef', 'hex'));
    });

    it('treats invalid base64 as utf8 (no throw)', async () => {
      expect(decodeBinaryAuto('Zm9=')).toEqual(Buffer.from('Zm9=', 'utf8'));
    });
  });

  describe('looksLikeHex', () => {
    it('returns true for a valid hex string', async () => {
      expect(looksLikeHex('deadbeef')).toBe(true);
    });

    it('returns true for uppercase hex', async () => {
      expect(looksLikeHex('DEADBEEF')).toBe(true);
    });

    it('returns true for 0x-prefixed hex', async () => {
      expect(looksLikeHex('0xdeadbeef')).toBe(true);
    });

    it('returns true for 0X-prefixed hex with separators', async () => {
      expect(looksLikeHex('0XDE AD')).toBe(true);
    });

    it('returns true for colon-separated hex', async () => {
      expect(looksLikeHex('de:ad:be:ef')).toBe(true);
    });

    it('returns true for mixed separators (spaces, hyphens, commas)', async () => {
      expect(looksLikeHex('de-ad be,ef')).toBe(true);
    });

    it('returns false for odd-length strings', async () => {
      expect(looksLikeHex('abc')).toBe(false);
    });

    it('returns false for non-hex characters', async () => {
      expect(looksLikeHex('0x0g')).toBe(false);
    });

    it('returns false for empty string', async () => {
      expect(looksLikeHex('')).toBe(false);
    });

    it('returns false for only prefix', async () => {
      expect(looksLikeHex('0x')).toBe(false);
    });

    it('returns false when separators are not recognized (e.g., underscore)', async () => {
      expect(looksLikeHex('aabb__ccdd')).toBe(false);
    });
  });

  describe('looksLikeBase64', () => {
    it('returns true for valid unpadded base64', async () => {
      expect(looksLikeBase64('Zm9v')).toBe(true);
    });

    it('returns true for valid padded base64', async () => {
      expect(looksLikeBase64('Zg==')).toBe(true);
    });

    it('returns true for base64 containing + and /', async () => {
      expect(looksLikeBase64('+w==')).toBe(true);
      expect(looksLikeBase64('/w==')).toBe(true);
    });

    it('returns true for valid base64 with whitespace', async () => {
      expect(looksLikeBase64('Zm 9v\n')).toBe(true);
    });

    it('returns false for empty string', async () => {
      expect(looksLikeBase64('')).toBe(false);
    });

    it('returns false when length is not a multiple of 4', async () => {
      expect(looksLikeBase64('Zg=')).toBe(false);
      expect(looksLikeBase64('Zm9vYg')).toBe(false);
    });

    it('returns false for invalid characters', async () => {
      expect(looksLikeBase64('Zm9v*')).toBe(false);
      expect(looksLikeBase64('-w==')).toBe(false);
      expect(looksLikeBase64('_w==')).toBe(false);
    });

    it('returns false for too much padding', async () => {
      expect(looksLikeBase64('Zg===')).toBe(false);
    });

    it('returns false for padding in the middle', async () => {
      expect(looksLikeBase64('Zg==Zg==')).toBe(false);
    });

    it('returns false when base64 decodes but fails canonical roundtrip', async () => {
      expect(looksLikeBase64('Zm9=')).toBe(false);
    });
  });

  describe('looksLikeUrlEncoded', () => {
    it('returns true when it contains %XX sequences', async () => {
      expect(looksLikeUrlEncoded('%7B%7D')).toBe(true);
    });

    it('returns true when it contains +', async () => {
      expect(looksLikeUrlEncoded('a+b')).toBe(true);
    });

    it('returns false for plain text', async () => {
      expect(looksLikeUrlEncoded('plain text')).toBe(false);
    });

    it('returns false for % not followed by two hex digits', async () => {
      expect(looksLikeUrlEncoded('100% sure')).toBe(false);
      expect(looksLikeUrlEncoded('%zz')).toBe(false);
    });

    it('treats literal + as a signal even if not truly encoded', async () => {
      expect(looksLikeUrlEncoded('x+y+z')).toBe(true);
    });
  });

  describe('decodeUrl', () => {
    it('decodes %XX sequences', async () => {
      expect(decodeUrl('hello%20world')).toBe('hello world');
    });

    it('treats + as space', async () => {
      expect(decodeUrl('a+b')).toBe('a b');
    });

    it('does not treat %2B as space', async () => {
      expect(decodeUrl('a%2Bb')).toBe('a+b');
    });

    it('decodes UTF-8 percent-encoded sequences', async () => {
      expect(decodeUrl('%E4%BD%A0%E5%A5%BD')).toBe('你好');
    });

    it('decodes mixed reserved characters', async () => {
      expect(decodeUrl('x%2Fy%3Fz%3D1')).toBe('x/y?z=1');
    });

    it('returns empty string for empty input', async () => {
      expect(decodeUrl('')).toBe('');
    });

    it('decodes %25 back to %', async () => {
      expect(decodeUrl('100%25')).toBe('100%');
    });
  });

  describe('encodeUrlBytes', () => {
    it('passes through unreserved characters', async () => {
      const input = Buffer.from('AZaz09-._~', 'ascii');
      expect(encodeUrlBytes(input)).toBe('AZaz09-._~');
    });

    it('encodes spaces as %20', async () => {
      expect(encodeUrlBytes(Buffer.from('a b', 'ascii'))).toBe('a%20b');
    });

    it('encodes reserved/special ASCII characters using %XX', async () => {
      expect(encodeUrlBytes(Buffer.from('/?:#[]@', 'ascii'))).toBe('%2F%3F%3A%23%5B%5D%40');
    });

    it('encodes % as %25', async () => {
      expect(encodeUrlBytes(Buffer.from('%', 'ascii'))).toBe('%25');
    });

    it('encodes + as %2B (not as +)', async () => {
      expect(encodeUrlBytes(Buffer.from('+', 'ascii'))).toBe('%2B');
    });

    it('encodes raw bytes outside ASCII using uppercase hex', async () => {
      expect(encodeUrlBytes(Buffer.from([0xff, 0xab, 0x00]))).toBe('%FF%AB%00');
    });

    it('encodes newline as %0A', async () => {
      expect(encodeUrlBytes(Buffer.from([0x0a]))).toBe('%0A');
    });

    it('percent-encodes UTF-8 bytes of non-ASCII text', async () => {
      expect(encodeUrlBytes(Buffer.from('你好', 'utf8'))).toBe('%E4%BD%A0%E5%A5%BD');
    });

    it('returns empty string for empty buffer', async () => {
      expect(encodeUrlBytes(Buffer.alloc(0))).toBe('');
    });
  });

  describe('toSafeUtf8', () => {
    it('returns empty string for empty buffer', async () => {
      expect(toSafeUtf8(Buffer.alloc(0))).toBe('');
    });

    it('returns utf8 text for valid ASCII', async () => {
      expect(toSafeUtf8(Buffer.from('hello', 'utf8'))).toBe('hello');
    });

    it('returns utf8 text for valid unicode', async () => {
      expect(toSafeUtf8(Buffer.from('你好', 'utf8'))).toBe('你好');
    });

    it('returns null when decoding introduces U+FFFD from invalid UTF-8', async () => {
      // Invalid 2-byte sequence: 0xC3 must be followed by 0x80..0xBF.
      expect(toSafeUtf8(Buffer.from([0xc3, 0x28]))).toBeNull();
    });

    it('returns null when the resulting text contains the replacement character (U+FFFD)', async () => {
      expect(toSafeUtf8(Buffer.from('\uFFFD', 'utf8'))).toBeNull();
    });

    it('returns null when valid text contains U+FFFD anywhere', async () => {
      expect(toSafeUtf8(Buffer.from(`ok\uFFFD`, 'utf8'))).toBeNull();
    });
  });

  describe('tryParseJson', () => {
    it('parses valid object JSON', async () => {
      expect(tryParseJson('{"ok":true}')).toEqual({ ok: true });
    });

    it('parses valid array JSON', async () => {
      expect(tryParseJson('[1,2,3]')).toEqual([1, 2, 3]);
    });

    it('parses valid number JSON', async () => {
      expect(tryParseJson('123')).toBe(123);
    });

    it('parses valid string JSON', async () => {
      expect(tryParseJson('"str"')).toBe('str');
    });

    it('parses valid null JSON', async () => {
      expect(tryParseJson('null')).toBeNull();
    });

    it('returns null for invalid JSON', async () => {
      expect(tryParseJson('{')).toBeNull();
      expect(tryParseJson('not json')).toBeNull();
    });

    it('returns null for JSON with trailing comma', async () => {
      expect(tryParseJson('{ "a": 1, }')).toBeNull();
      expect(tryParseJson('[1,2,]')).toBeNull();
    });

    it('handles leading/trailing whitespace for valid JSON', async () => {
      expect(tryParseJson(' \n\t {"a":1} \n')).toEqual({ a: 1 });
    });
  });
});

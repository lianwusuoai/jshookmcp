/**
 * Protocol-analysis domain benchmark.
 *
 * External vectors:
 *  - RFC 1071 §3 worked example (internet checksum: 00 01 f2 03 f4 f5 f6 f7 → 0x220d)
 *  - RFC 1035 §4.1.2-style DNS query (www.example.com A IN) — same wire layout as
 *    the "example.com" query in the RFC and in the Wireshark SampleCaptures dns.cards
 *  - RFC 7230 HTTP/1.1 GET request layout
 * Homemade fixtures:
 *  - Ethernet II frame build determinism
 *  - pcap write → read roundtrip
 *  - ICMP echo checksum self-consistency
 */
import { ProtocolAnalysisHandlers } from '@server/domains/protocol-analysis/handlers';
import { body, type BenchSuite } from '../harness';

const handlers = new ProtocolAnalysisHandlers({} as never);

// DNS query: id=0x1234, RD, 1 question, www.example.com A IN
const DNS_QUERY_HEX =
  '1234' + // id
  '0100' + // flags: RD
  '0001' + // qdcount
  '00000000000003777777076578616d706c6503636f6d00' + // www.example.com
  '00010001'; // QTYPE=A QCLASS=IN

const HTTP_REQUEST = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\n\r\n';
const HTTP_REQUEST_HEX = Buffer.from(HTTP_REQUEST, 'utf8').toString('hex');

export const protocolSuite: BenchSuite = {
  name: 'protocol-analysis',
  domain: 'protocol-analysis',
  description:
    'checksum/DNS/HTTP dissection + packet builders + pcap roundtrip — RFC vectors and deterministic builders',
  cases: [
    {
      name: 'checksum_apply/rfc1071-worked-example',
      tool: 'checksum_apply',
      origin: 'external-vector',
      reference: 'RFC 1071 §3 worked example (00 01 f2 03 f4 f5 f6 f7 ⇒ checksum 0x220d)',
      run: () => handlers.handleChecksumApply({ hexPayload: '0001f203f4f5f6f7' }),
      validate: (v) => {
        const b = v as {
          checksum?: number;
          checksumHex?: string;
          success?: boolean;
          error?: string;
        };
        if (b.success === false) return `tool failed: ${b.error}`;
        if (b.checksum !== 0x220d)
          return `expected 0x220d (8909), got ${b.checksum} (${b.checksumHex})`;
        return true;
      },
    },
    {
      name: 'proto_dissect_dns/example-com-query',
      tool: 'proto_dissect_dns',
      origin: 'external-vector',
      reference: 'RFC 1035 §4.1 query wire layout (www.example.com A IN, RD=1)',
      run: () => handlers.handleProtoDissectDns({ packetHex: DNS_QUERY_HEX }),
      validate: (v) => {
        const b = v as {
          message?: { questions?: Array<{ name?: string; qtype?: number }> };
          error?: string;
          success?: boolean;
        };
        if (b.success === false) return `tool failed: ${b.error}`;
        const q = b.message?.questions?.[0];
        if (!q) return 'no question parsed';
        if (q.name !== 'www.example.com') return `expected name www.example.com, got ${q.name}`;
        if (q.qtype !== 1) return `expected qtype 1 (A), got ${q.qtype}`;
        return true;
      },
    },
    {
      name: 'proto_dissect_http/get-request',
      tool: 'proto_dissect_http',
      origin: 'external-vector',
      reference: 'RFC 7230 request-line + headers wire layout',
      run: () => handlers.handleProtoDissectHttp({ packetHex: HTTP_REQUEST_HEX }),
      validate: (v) => {
        const b = v as {
          message?: { kind?: string; method?: string; requestTarget?: string; headers?: unknown[] };
          error?: string;
          success?: boolean;
        };
        if (b.success === false) return `tool failed: ${b.error}`;
        const m = b.message;
        if (!m) return 'no message parsed';
        if (m.kind !== 'request') return `expected kind=request, got ${m.kind}`;
        if (m.method !== 'GET') return `expected method GET, got ${m.method}`;
        if (m.requestTarget !== '/index.html')
          return `expected requestTarget /index.html, got ${m.requestTarget}`;
        if (!m.headers || m.headers.length !== 2)
          return `expected 2 headers, got ${m.headers?.length}`;
        return true;
      },
    },
    {
      name: 'ethernet_frame_build/deterministic-ipv4',
      tool: 'ethernet_frame_build',
      origin: 'homemade',
      reference: 'Ethernet II: 6B dst + 6B src + 2B etherType — layout is normative',
      run: () =>
        handlers.handleEthernetFrameBuild({
          destinationMac: 'AA:BB:CC:DD:EE:FF',
          sourceMac: '11:22:33:44:55:66',
          etherType: '0x0800',
          payloadHex: '45000014000000004011f9a5c0a80001c0a80002',
        }),
      validate: (v) => {
        const b = v as {
          frameHex?: string;
          byteLength?: number;
          success?: boolean;
          error?: string;
        };
        if (b.success === false) return `tool failed: ${b.error}`;
        const expected = 'aabbccddeeff112233445566080045000014000000004011f9a5c0a80001c0a80002';
        if (b.frameHex !== expected) return `frame mismatch, got ${b.frameHex}`;
        if (b.byteLength !== expected.length / 2) return `byteLength mismatch, got ${b.byteLength}`;
        return true;
      },
    },
    {
      name: 'icmp_echo_build/checksum-valid',
      tool: 'icmp_echo_build',
      origin: 'homemade',
      reference:
        'ICMP echo reply must carry the same checksum as the echo request (RFC 1072 layout)',
      run: async () => {
        const req = (await handlers.handleIcmpEchoBuild({
          operation: 'request',
          identifier: 0x1234,
          sequenceNumber: 7,
          payloadHex: '6a73686f6f6b',
        })) as { packetHex?: string; checksum?: number; success?: boolean; error?: string };
        const reply = (await handlers.handleIcmpEchoBuild({
          operation: 'reply',
          identifier: 0x1234,
          sequenceNumber: 7,
          payloadHex: '6a73686f6f6b',
        })) as { checksum?: number; success?: boolean; error?: string };
        return { req, reply };
      },
      validate: (v) => {
        const { req, reply } = v as {
          req: { checksum?: number; packetHex?: string };
          reply: { checksum?: number; packetHex?: string };
        };
        if (!req.checksum || !reply.checksum) return 'missing checksums';
        // RFC 1071: each packet's checksum must make its own 16-bit word sum 0xFFFF.
        // (Request vs reply checksums legitimately differ: the type byte is covered.)
        for (const [label, pkt] of [
          ['request', req],
          ['reply', reply],
        ] as const) {
          const bytes = Buffer.from(pkt.packetHex ?? '', 'hex');
          let sum = 0;
          for (let i = 0; i < bytes.length; i += 2) {
            sum += bytes.readUInt16BE(i);
          }
          while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
          if (sum !== 0xffff)
            return `${label} packet checksum sum is ${sum.toString(16)}, expected ffff`;
        }
        return true;
      },
    },
    {
      name: 'pcap_write+read/roundtrip',
      tool: 'pcap_write',
      origin: 'homemade',
      reference: 'classic pcap (libpcap) global header + per-packet headers must roundtrip',
      run: async () => {
        const path = `/tmp/jshook-bench-${process.pid}-${Date.now()}.pcap`;
        const eth = 'aabbccddeeff112233445566080045000014000000004011f9a5c0a80001c0a80002';
        const w = (await handlers.handlePcapWrite({
          path,
          packets: [{ dataHex: eth, timestampSeconds: 1700000000, timestampFraction: 123456 }],
        })) as { success?: boolean; error?: string; packetCount?: number };
        if (w.success === false) throw new Error(`pcap_write failed: ${w.error}`);
        return handlers.handlePcapRead({ path });
      },
      validate: (v) => {
        const b = v as {
          packets?: Array<{ dataHex?: string; capturedLength?: number }>;
          header?: { magic?: string };
          success?: boolean;
          error?: string;
        };
        if (b.success === false) return `read failed: ${b.error}`;
        if (!Array.isArray(b.packets) || b.packets.length !== 1)
          return `expected 1 packet, got ${b.packets?.length}`;
        const first = b.packets[0];
        if (!first?.dataHex?.startsWith('aabbccddeeff1122334455660800'))
          return `payload mismatch, got ${first?.dataHex?.slice(0, 30)}`;
        return true;
      },
    },
    {
      name: 'proto_fingerprint/dns-vs-http',
      tool: 'proto_fingerprint',
      origin: 'homemade',
      reference:
        'protocol identification: DNS query payload must not classify as HTTP and vice versa',
      run: async () => {
        const dns = (await handlers.handleProtoFingerprint({
          hexPayloads: [DNS_QUERY_HEX],
        })) as {
          fingerprints?: Array<{ protocolMatches?: Array<{ protocol?: string }> }>;
          success?: boolean;
          error?: string;
        };
        const http = (await handlers.handleProtoFingerprint({
          hexPayloads: [HTTP_REQUEST_HEX],
        })) as {
          fingerprints?: Array<{ protocolMatches?: Array<{ protocol?: string }> }>;
          success?: boolean;
          error?: string;
        };
        return { dns, http };
      },
      validate: (v) => {
        const { dns, http } = v as { dns: unknown; http: unknown };
        const protocolsOf = (r: unknown, i = 0) => {
          const parsed = body(r) as {
            fingerprints?: Array<{ protocolMatches?: Array<{ protocol?: string }> }>;
          };
          return (parsed.fingerprints?.[i]?.protocolMatches ?? []).map((m) =>
            (m.protocol ?? '').toLowerCase(),
          );
        };
        const httpProtos = protocolsOf(http);
        if (!httpProtos.some((p) => p.includes('http')))
          return `HTTP payload not matched as http: ${JSON.stringify(protocolsOf(http)).slice(0, 160)}`;
        const dnsProtos = protocolsOf(dns);
        if (dnsProtos.some((p) => p.includes('http')))
          return `DNS payload misclassified as http: ${JSON.stringify(dnsProtos).slice(0, 160)}`;
        if (!dnsProtos.some((p) => p.includes('dns')))
          return `DNS payload not matched as DNS: ${JSON.stringify(dnsProtos).slice(0, 160)}`;
        return true;
      },
    },
  ],
};

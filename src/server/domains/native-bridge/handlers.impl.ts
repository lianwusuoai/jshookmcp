// ── Types ──

import {
  GHIDRA_BRIDGE_ENDPOINT,
  IDA_BRIDGE_ENDPOINT,
  NATIVE_BRIDGE_TIMEOUT_MS,
} from '@src/constants';
import { handleSafe, type ToolResponse } from '@server/domains/shared/ResponseBuilder';
import { asJsonResponse, serializeError } from '@server/domains/shared/response';
import {
  getGlobalInstrumentation,
  MetricNames,
  SpanNames,
} from '@server/observability/InstrumentationContract';
import {
  describeGhidraBridgeTcpError,
  GhidraBridgeTcpError,
  ghidraBridgePing,
  logGhidraBridgeTcpWarning,
} from './ghidra-bridge-tcp';
import { dispatchTcpAction, tcpStatus } from './ghidra-bridge-tcp-actions';
import {
  buildActionBody,
  HTTP_ACTIONS_BY_BACKEND,
  REQUIRED_ARG_BY_KIND,
  RESPONSE_KEY_BY_KIND,
  resolveActionPath,
  STATIC_ACTIONS_BY_BACKEND,
  type HttpActionRecipe,
} from './http-actions';
const RIZIN_BRIDGE_ENDPOINT = 'http://127.0.0.1:18082';
const BINARY_NINJA_BRIDGE_ENDPOINT = 'http://127.0.0.1:18083';

interface BridgeResponse {
  status: number;
  data: unknown;
}

export type BridgeBackend = 'ghidra' | 'ida' | 'rizin' | 'binaryninja';

// ── Helpers ──

function toErrorResponse(tool: string, error: unknown, extra: Record<string, unknown> = {}) {
  return asJsonResponse({ ...serializeError(error), tool, ...extra });
}

async function bridgeFetch(
  baseUrl: string,
  path: string,
  method = 'GET',
  body?: string,
): Promise<BridgeResponse> {
  const url = `${baseUrl.replace(/\/$/, '')}${path}`;
  // Process-global rather than context-resolved: this is a module-level helper
  // that receives no server context, and all four `handle*Bridge` methods funnel
  // through it, so one span covers every backend. A thrown fetch (timeout,
  // connection refused) is the interesting case for a bridge, so the `finally`
  // records it as a transport error before the error propagates.
  const instrumentation = getGlobalInstrumentation();
  const span = instrumentation.startSpan(SpanNames.bridgeRequest, { url, method });
  const startedAtMs = Date.now();
  let status = 'transport_error';
  try {
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(NATIVE_BRIDGE_TIMEOUT_MS),
    });
    // Parse failure (non-JSON body) yields null so health checks do not treat
    // a misconfigured 200 HTML error page as a healthy bridge.
    const data = await res.json().catch(() => null);
    status = String(res.status);
    return { status: res.status, data };
  } catch (error) {
    span.addEvent('error', { message: error instanceof Error ? error.message : String(error) });
    throw error;
  } finally {
    const durationMs = Date.now() - startedAtMs;
    span.end({ status });
    instrumentation.emitMetric(MetricNames.bridgeRequestsTotal, 1, 'counter', { status });
    instrumentation.emitMetric(MetricNames.bridgeDurationMs, durationMs, 'histogram', {
      method,
      status,
    });
  }
}

/**
 * Generic HTTP bridge action dispatcher — turns a recipe from http-actions.ts
 * into a bridgeFetch + response pair. Replaces the four per-backend switch
 * statements (the largest clone family in the repo audit).
 */
async function dispatchHttpBridgeAction(
  action: string,
  args: Record<string, unknown>,
  recipe: HttpActionRecipe,
  endpoint: string,
): Promise<ReturnType<typeof asJsonResponse>> {
  const requiredArg = REQUIRED_ARG_BY_KIND[recipe.kind];
  if (requiredArg && !args[requiredArg]) {
    throw new Error(`${requiredArg} is required for ${action}`);
  }

  const method = recipe.body ? 'POST' : 'GET';
  const { status, data } = await bridgeFetch(
    endpoint,
    resolveActionPath(recipe, args),
    method,
    buildActionBody(recipe, args),
  );

  const payload: Record<string, unknown> = { success: status < 300, action };
  const responseKey = RESPONSE_KEY_BY_KIND[recipe.kind];
  if (responseKey) {
    payload[responseKey] = data;
  } else if (recipe.kind === 'strings_post' || recipe.kind === 'strings_get') {
    payload.strings = data;
  } else if (
    recipe.kind === 'open' ||
    recipe.kind === 'open_project' ||
    recipe.kind === 'run_script' ||
    recipe.kind === 'run_command' ||
    recipe.kind === 'analyze'
  ) {
    payload.result = data;
  } else if (recipe.extra) {
    for (const [key, marker] of Object.entries(recipe.extra)) {
      if (marker === null) payload[key] = data;
      else payload[key] = marker;
    }
  }

  // Decompile/xrefs echo the resolved argument alongside the payload.
  if (recipe.kind === 'decompile' || recipe.kind === 'disassemble' || recipe.kind === 'xrefs') {
    payload.functionName = args.functionName;
    if (recipe.kind === 'xrefs') payload.symbol = args.functionName;
  }

  return asJsonResponse(payload);
}

async function checkBridgeHealth(
  endpoint: string,
  label: BridgeBackend,
): Promise<Record<string, unknown>> {
  try {
    const { status, data } = await bridgeFetch(endpoint, '/health');
    const advertised = await checkBridgeCapabilities(endpoint, label);
    return {
      backend: label,
      // A 200 with a non-JSON body is a misconfigured sidecar, not a healthy bridge.
      available: status === 200 && data !== null,
      endpoint,
      version: data,
      capabilities: advertised.actions,
      capabilitySource: advertised.source,
    };
  } catch (error) {
    return {
      backend: label,
      available: false,
      endpoint,
      error: error instanceof Error ? error.message : String(error),
      capabilities: getStaticActions(label),
      capabilitySource: 'static',
    };
  }
}

async function checkBridgeCapabilities(
  endpoint: string,
  backend: BridgeBackend,
): Promise<{ actions: string[]; source: 'remote' | 'static' }> {
  try {
    const { status, data } = await bridgeFetch(endpoint, '/capabilities');
    if (status >= 200 && status < 300) {
      const remoteActions = parseCapabilityActions(data);
      if (remoteActions.length > 0) {
        return { actions: remoteActions, source: 'remote' };
      }
    }
  } catch (error) {
    void error;
    // Older bridge servers may not implement /capabilities.
  }
  return { actions: getStaticActions(backend), source: 'static' };
}

function getStaticActions(backend: BridgeBackend): string[] {
  return [...STATIC_ACTIONS_BY_BACKEND[backend]];
}

function parseCapabilityActions(data: unknown): string[] {
  if (Array.isArray(data)) {
    return data.filter((item): item is string => typeof item === 'string');
  }
  if (!data || typeof data !== 'object') {
    return [];
  }

  const record = data as Record<string, unknown>;
  for (const key of ['actions', 'capabilities', 'supportedActions']) {
    const value = record[key];
    if (Array.isArray(value)) {
      return value.filter((item): item is string => typeof item === 'string');
    }
  }
  return [];
}

// ── Endpoint validation ──

function validateLoopbackEndpoint(endpoint: string, label: string): void {
  const parsed = new URL(endpoint);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${label}: only http/https protocols allowed, got ${parsed.protocol}`);
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1';
  if (!isLoopback) {
    throw new Error(
      `${label}: only loopback addresses allowed (127.0.0.1/localhost/::1), got ${host}`,
    );
  }
}

// ── Handler class ──

export class NativeBridgeHandlers {
  private readonly ghidraEndpoint: string;
  private readonly idaEndpoint: string;
  private readonly rizinEndpoint: string;
  private readonly binaryNinjaEndpoint: string;

  constructor(
    ghidraEndpoint = GHIDRA_BRIDGE_ENDPOINT,
    idaEndpoint = IDA_BRIDGE_ENDPOINT,
    rizinEndpoint = RIZIN_BRIDGE_ENDPOINT,
    binaryNinjaEndpoint = BINARY_NINJA_BRIDGE_ENDPOINT,
  ) {
    // Validate endpoints are loopback only (SSRF protection)
    validateLoopbackEndpoint(ghidraEndpoint, 'Ghidra bridge');
    validateLoopbackEndpoint(idaEndpoint, 'IDA bridge');
    validateLoopbackEndpoint(rizinEndpoint, 'Rizin bridge');
    validateLoopbackEndpoint(binaryNinjaEndpoint, 'Binary Ninja bridge');
    this.ghidraEndpoint = ghidraEndpoint;
    this.idaEndpoint = idaEndpoint;
    this.rizinEndpoint = rizinEndpoint;
    this.binaryNinjaEndpoint = binaryNinjaEndpoint;
  }

  /** Endpoints are fixed at construction; user args cannot override them. */
  private getGhidraEndpoint(_args: Record<string, unknown>): string {
    return this.ghidraEndpoint;
  }

  private getIdaEndpoint(_args: Record<string, unknown>): string {
    return this.idaEndpoint;
  }

  private getRizinEndpoint(_args: Record<string, unknown>): string {
    return this.rizinEndpoint;
  }

  private getBinaryNinjaEndpoint(_args: Record<string, unknown>): string {
    return this.binaryNinjaEndpoint;
  }

  handleNativeBridgeStatusTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(() => this.handleNativeBridgeStatus(args));
  }

  handleGhidraBridgeTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(() => this.handleGhidraBridge(args));
  }

  // Bound by string name in manifest.ts defineMethodRegistrations — invisible
  // to static analysis.
  // fallow-ignore-next-line unused-class-member
  handleIdaBridgeTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(() => this.handleIdaBridge(args));
  }

  // Bound by string name in manifest.ts defineMethodRegistrations — invisible
  // to static analysis.
  // fallow-ignore-next-line unused-class-member
  handleRizinBridgeTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(() => this.handleRizinBridge(args));
  }

  // Bound by string name in manifest.ts defineMethodRegistrations — invisible
  // to static analysis.
  // fallow-ignore-next-line unused-class-member
  handleBinaryNinjaBridgeTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(() => this.handleBinaryNinjaBridge(args));
  }

  // Bound by string name in manifest.ts defineMethodRegistrations — invisible
  // to static analysis.
  // fallow-ignore-next-line unused-class-member
  handleNativeSymbolSyncTool(args: Record<string, unknown>): Promise<ToolResponse> {
    return handleSafe(() => this.handleNativeSymbolSync(args));
  }

  async handleNativeBridgeStatus(args: Record<string, unknown>) {
    const backend = (args.backend as string) || 'all';
    const results: Record<string, unknown>[] = [];

    if (backend === 'ghidra' || backend === 'all') {
      results.push(await checkBridgeHealth(this.getGhidraEndpoint(args), 'ghidra'));
    }
    if (backend === 'ida' || backend === 'all') {
      results.push(await checkBridgeHealth(this.getIdaEndpoint(args), 'ida'));
    }
    if (backend === 'rizin' || backend === 'all') {
      results.push(await checkBridgeHealth(this.getRizinEndpoint(args), 'rizin'));
    }
    if (backend === 'binaryninja' || backend === 'all') {
      results.push(await checkBridgeHealth(this.getBinaryNinjaEndpoint(args), 'binaryninja'));
    }

    return asJsonResponse({
      success: true,
      backends: results,
      hint:
        'Install bridge servers: Ghidra → ghidra_bridge, IDA → ida_bridge, ' +
        'Rizin → local rizin/r2 bridge, Binary Ninja → local Binary Ninja bridge',
    });
  }

  async handleGhidraBridge(args: Record<string, unknown>) {
    const action = args.action as string;
    const endpoint = this.getGhidraEndpoint(args);

    if (!action) {
      return toErrorResponse('ghidra_bridge', new Error('action is required'));
    }

    // Backend routing (kimi-cu report P2-6): 'ghidra-bridge-py' targets the
    // pip ghidra_bridge TCP server (127.0.0.1:4768, jfx-bridge v5 wire
    // protocol), 'http' targets a REST bridge server (default 18080).
    // Unset = auto: status reports both bridges in one call; every other
    // action prefers the pip TCP server when it answers a ping, and falls
    // back to the REST bridge for actions the TCP backend does not map
    // (open_project) instead of failing just because the TCP server runs.
    const backend = args.backend as string | undefined;
    if (backend === undefined && action === 'status') {
      return this.handleGhidraBridgeStatusAuto(endpoint);
    }
    if (backend === 'ghidra-bridge-py') {
      return this.handleGhidraBridgeTcp(args, action);
    }
    if (backend === 'http') {
      return this.handleGhidraBridgeHttp(args, action, endpoint);
    }

    const tcpReachable = await ghidraBridgePing().then(
      () => true,
      () => false,
    );
    if (tcpReachable) {
      return this.handleGhidraBridgeTcp(args, action, () =>
        this.handleGhidraBridgeHttp(args, action, endpoint, true),
      );
    }
    return this.handleGhidraBridgeHttp(args, action, endpoint);
  }

  /**
   * Auto-mode status: one call reports both bridges so agents can see which
   * is wired up without running two probes.
   */
  private async handleGhidraBridgeStatusAuto(
    endpoint: string,
  ): Promise<ReturnType<typeof asJsonResponse>> {
    const [http, tcp] = await Promise.allSettled([
      checkBridgeHealth(endpoint, 'ghidra'),
      tcpStatus(),
    ]);
    const httpResult =
      http.status === 'fulfilled'
        ? (http.value as Record<string, unknown>)
        : { success: false, reason: String(http.reason) };
    const tcpResult =
      tcp.status === 'fulfilled'
        ? (tcp.value as Record<string, unknown>)
        : {
            success: true,
            action: 'status',
            backend: 'ghidra-bridge-py',
            reachable: false,
            reason: describeGhidraBridgeTcpError(tcp.reason).reason,
          };
    return asJsonResponse({ ...httpResult, tcpBackend: tcpResult });
  }

  /**
   * REST bridge backend (default 18080).
   *
   * `tcpAlreadyTried` is set by the auto-mode fallback: it means this call is
   * the second half of "TCP declined, try HTTP", so an unmapped action can be
   * reported as missing from both backends rather than pointing the caller at
   * the other one.
   */
  private async handleGhidraBridgeHttp(
    args: Record<string, unknown>,
    action: string,
    endpoint: string,
    tcpAlreadyTried = false,
  ): Promise<ReturnType<typeof asJsonResponse>> {
    try {
      if (action === 'status') {
        return asJsonResponse(await checkBridgeHealth(endpoint, 'ghidra'));
      }
      const recipe = HTTP_ACTIONS_BY_BACKEND.ghidra[action];
      if (recipe) {
        return await dispatchHttpBridgeAction(action, args, recipe, endpoint);
      }
      // Not `success: true`: the schema advertises a fixed action list, so
      // reaching here means the action has no HTTP mapping (or was added
      // to the schema and one backend but not this one). Reporting success
      // with a guide payload makes that silent — the caller sees `true`
      // and no result. TCP auto-mode falls back to this branch for every
      // action it does not map, so the failure has to be explicit.
      //
      // Auto-mode fallback has already had the TCP backend decline this
      // action, so say so: "not on http" alone reads as a one-sided
      // failure the caller could fix by pinning the other backend.
      return asJsonResponse({
        success: false,
        action,
        backend: 'http',
        ...(tcpAlreadyTried
          ? {
              triedBackends: ['ghidra-bridge-py', 'http'],
              reason: `action "${action}" has no mapping on either Ghidra backend (pip TCP or REST http)`,
            }
          : {
              reason: `action "${action}" is not available on the Ghidra REST (http) backend`,
            }),
        guide: {
          what: 'Ghidra is an open-source SRE framework by NSA.',
          actions: [...STATIC_ACTIONS_BY_BACKEND.ghidra],
          backends: {
            'ghidra-bridge-py (recommended, pip)':
              'pip install ghidra_bridge, then in Ghidra: File → Run Script → ghidra_bridge_server.py — listens on 127.0.0.1:4768 (TCP)',
            'http (REST bridge)':
              'Run a REST bridge server on http://127.0.0.1:18080 (GHIDRA_BRIDGE_URL to override)',
          },
          links: ['https://ghidra-sre.org/', 'https://github.com/justfoxing/ghidra_bridge'],
        },
      });
    } catch (error) {
      return toErrorResponse('ghidra_bridge', error, { action, endpoint });
    }
  }

  /**
   * pip ghidra_bridge TCP backend (kimi-cu report P2-6): the tool used to
   * advertise `pip install ghidra_bridge` while speaking REST only — the pip
   * server is a TCP server on 4768, so the advertised setup never worked.
   * This path speaks the actual jfx-bridge v5 wire protocol. `httpFallback`
   * (auto mode) takes over for actions with no TCP mapping.
   */
  private async handleGhidraBridgeTcp(
    args: Record<string, unknown>,
    action: string,
    httpFallback?: () => Promise<ReturnType<typeof asJsonResponse>>,
  ): Promise<ReturnType<typeof asJsonResponse>> {
    try {
      const result = await dispatchTcpAction(action, args);
      if (!result) {
        // Auto mode: an HTTP-only action (open_project) must not fail just
        // because the pip TCP server happens to be running.
        if (httpFallback) {
          return httpFallback();
        }
        return asJsonResponse({
          success: false,
          action,
          backend: 'ghidra-bridge-py',
          reason: `action "${action}" is not available on the pip ghidra_bridge TCP backend`,
          ...(action === 'open_project'
            ? { fix: 'Open the project in the Ghidra GUI first, then re-run this tool.' }
            : {}),
        });
      }
      return asJsonResponse(result);
    } catch (error) {
      logGhidraBridgeTcpWarning(action, error);
      return asJsonResponse({
        ...serializeError(error),
        tool: 'ghidra_bridge',
        action,
        backend: 'ghidra-bridge-py',
        reason: describeGhidraBridgeTcpError(error).reason,
        // Install guidance only for transport-level failures — an argument
        // validation error ("functionName is required") is not fixed by
        // installing anything.
        ...(error instanceof GhidraBridgeTcpError
          ? {
              fix: 'pip install ghidra_bridge, then in Ghidra: File → Run Script → ghidra_bridge_server.py (listens on 127.0.0.1:4768)',
            }
          : {}),
      });
    }
  }

  async handleIdaBridge(args: Record<string, unknown>) {
    const action = args.action as string;
    const endpoint = this.getIdaEndpoint(args);

    if (!action) {
      return toErrorResponse('ida_bridge', new Error('action is required'));
    }

    try {
      if (action === 'status') {
        return asJsonResponse(await checkBridgeHealth(endpoint, 'ida'));
      }
      const recipe = HTTP_ACTIONS_BY_BACKEND.ida[action];
      if (recipe) {
        return await dispatchHttpBridgeAction(action, args, recipe, endpoint);
      }
      return asJsonResponse({
        success: true,
        guide: {
          what: 'IDA Pro is a commercial disassembler/decompiler by Hex-Rays.',
          actions: [...STATIC_ACTIONS_BY_BACKEND.ida],
          bridgeSetup: [
            'pip install ida_bridge  // or use idalink',
            'In IDA: File → Script file → ida_bridge_server.py',
            'Default endpoint: http://127.0.0.1:18081',
          ],
          links: ['https://hex-rays.com/ida-pro/', 'https://github.com/williballenthin/ida-bridge'],
        },
      });
    } catch (error) {
      return toErrorResponse('ida_bridge', error, { action, endpoint });
    }
  }

  async handleRizinBridge(args: Record<string, unknown>) {
    const action = args.action as string;
    const endpoint = this.getRizinEndpoint(args);

    if (!action) {
      return toErrorResponse('rizin_bridge', new Error('action is required'));
    }

    try {
      if (action === 'status') {
        return asJsonResponse(await checkBridgeHealth(endpoint, 'rizin'));
      }
      const recipe = HTTP_ACTIONS_BY_BACKEND.rizin[action];
      if (recipe) {
        return await dispatchHttpBridgeAction(action, args, recipe, endpoint);
      }
      return asJsonResponse({
        success: true,
        guide: {
          what: 'Rizin/r2 is an open-source reverse engineering framework.',
          actions: [...STATIC_ACTIONS_BY_BACKEND.rizin],
          bridgeSetup: [
            'Start a loopback HTTP bridge that translates these routes to rizin/r2 commands',
            'Default endpoint: http://127.0.0.1:18082',
          ],
          links: ['https://rizin.re/', 'https://github.com/rizinorg/rizin'],
        },
      });
    } catch (error) {
      return toErrorResponse('rizin_bridge', error, { action, endpoint });
    }
  }

  async handleBinaryNinjaBridge(args: Record<string, unknown>) {
    const action = args.action as string;
    const endpoint = this.getBinaryNinjaEndpoint(args);

    if (!action) {
      return toErrorResponse('binary_ninja_bridge', new Error('action is required'));
    }

    try {
      if (action === 'status') {
        return asJsonResponse(await checkBridgeHealth(endpoint, 'binaryninja'));
      }
      const recipe = HTTP_ACTIONS_BY_BACKEND.binaryninja[action];
      if (recipe) {
        return await dispatchHttpBridgeAction(action, args, recipe, endpoint);
      }
      return asJsonResponse({
        success: true,
        guide: {
          what: 'Binary Ninja is a commercial reverse engineering platform.',
          actions: [...STATIC_ACTIONS_BY_BACKEND.binaryninja],
          bridgeSetup: [
            'Run a Binary Ninja plugin that exposes the loopback HTTP bridge routes',
            'Default endpoint: http://127.0.0.1:18083',
          ],
          links: ['https://binary.ninja/'],
        },
      });
    } catch (error) {
      return toErrorResponse('binary_ninja_bridge', error, { action, endpoint });
    }
  }

  async handleNativeSymbolSync(args: Record<string, unknown>) {
    const source = args.source as string;
    if (!source || !['ghidra', 'ida', 'rizin', 'binaryninja'].includes(source)) {
      return toErrorResponse(
        'native_symbol_sync',
        new Error('source must be one of: ghidra, ida, rizin, binaryninja'),
      );
    }

    const endpoint =
      source === 'ghidra'
        ? this.getGhidraEndpoint(args)
        : source === 'ida'
          ? this.getIdaEndpoint(args)
          : source === 'rizin'
            ? this.getRizinEndpoint(args)
            : this.getBinaryNinjaEndpoint(args);

    const sinceHash =
      typeof args.sinceHash === 'string' && args.sinceHash.trim().length > 0
        ? args.sinceHash.trim()
        : '';

    try {
      // Only forward sinceHash when provided so legacy backends see the same
      // body shape they always have (incremental export is opt-in per sync).
      const body: Record<string, unknown> = {
        filter: args.filter ?? '',
        format: args.exportFormat ?? 'json',
      };
      if (sinceHash) {
        body.sinceHash = sinceHash;
      }

      const { status, data } = await bridgeFetch(
        endpoint,
        '/symbols/export',
        'POST',
        JSON.stringify(body),
      );

      // Echo the requested sinceHash; callers persist data.nextSinceHash (or
      // data.hash) returned by the sidecar for the next incremental sync.
      return asJsonResponse({
        success: status < 300,
        source,
        format: args.exportFormat ?? 'json',
        ...(sinceHash ? { sinceHash } : {}),
        symbols: data,
      });
    } catch (error) {
      return toErrorResponse('native_symbol_sync', error, { source, endpoint });
    }
  }
}

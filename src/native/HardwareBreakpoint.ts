/**
 * Hardware Breakpoint Engine — x64 debug register management.
 *
 * Sets/clears hardware breakpoints using DR0–DR3, monitors for hits,
 * and returns access context (instruction address, thread, register state).
 *
 * @module HardwareBreakpoint
 */

import { BREAKPOINT_HIT_TIMEOUT_MS, BREAKPOINT_TRACE_MAX_HITS } from '@src/constants';
import { ToolError } from '@errors/ToolError';
import type {
  BreakpointAccess,
  BreakpointConfig,
  BreakpointHit,
  BreakpointListEntry,
  BreakpointSize,
} from './HardwareBreakpoint.types';
import {
  GetThreadContext,
  SetThreadContext,
  DebugActiveProcess,
  DebugActiveProcessStop,
  DebugSetProcessKillOnExit,
  WaitForDebugEvent,
  ContinueDebugEvent,
  openThreadForDebug,
  parseContext,
  CONTEXT_FLAGS,
  IS_ARM64_WINDOWS,
  EXCEPTION_CODE,
  DBG,
} from './Win32Debug';
import { CloseHandle } from './Win32API';
import {
  makeApplyDRAdapter,
  traceAccessShared,
  DR_ACCESS_MAP,
  type Dr7Entry,
  listBreakpointsShared,
  hitPollWindow,
  setBreakpointShared,
  removeBreakpointShared,
} from './breakpoint-registers';

const toHex = (v: bigint) => `0x${v.toString(16).toUpperCase()}`;

interface ActiveBreakpoint extends BreakpointConfig {
  drIndex: number;
  hitCount: number;
  lastHit?: number;
}

export class HardwareBreakpointEngine {
  private breakpoints = new Map<string, ActiveBreakpoint>();
  private attachedPids = new Set<number>();
  private drAllocation = [false, false, false, false]; // DR0–DR3

  /** Attach to process as debugger (required before setting breakpoints) */
  async attach(pid: number): Promise<void> {
    if (this.attachedPids.has(pid)) return;
    DebugActiveProcess(pid);
    DebugSetProcessKillOnExit(false);
    this.attachedPids.add(pid);

    // Consume initial debug events (CREATE_PROCESS, LOAD_DLL, etc.)
    for (let i = 0; i < 100; i++) {
      const evt = WaitForDebugEvent(100);
      if (!evt) break;
      ContinueDebugEvent(evt.processId, evt.threadId, DBG.CONTINUE);
    }
  }

  /** Detach from process */
  async detach(pid: number): Promise<void> {
    // Remove all breakpoints for this pid
    for (const [id, bp] of this.breakpoints) {
      if (bp.pid === pid) {
        // Delete before clearDR so the DR7 rebuild excludes this breakpoint
        // (otherwise its DR bit stays enabled with a zeroed address).
        this.breakpoints.delete(id);
        this.clearDR(pid, bp.drIndex);
        this.drAllocation[bp.drIndex] = false;
      }
    }

    if (this.attachedPids.has(pid)) {
      try {
        DebugActiveProcessStop(pid);
      } catch {
        // Best effort
      }
      this.attachedPids.delete(pid);
    }
  }

  /** List all active breakpoints */
  listBreakpoints(): BreakpointListEntry[] {
    return listBreakpointsShared(this.breakpoints.values());
  }

  /** Wait for a breakpoint hit */
  async waitForHit(timeoutMs?: number): Promise<BreakpointHit | null> {
    const deadline = hitPollWindow(timeoutMs).deadline;
    while (Date.now() < deadline) {
      const remaining = Math.max(100, deadline - Date.now());
      const evt = WaitForDebugEvent(Math.min(remaining, 500));

      if (!evt) continue;

      // Check for single-step exception (hardware breakpoint hit)
      if (evt.exceptionCode === EXCEPTION_CODE.SINGLE_STEP) {
        const hit = this.processHit(evt.threadId, evt.processId, evt.exceptionAddress);
        ContinueDebugEvent(evt.processId, evt.threadId, DBG.CONTINUE);
        if (hit) return hit;
      } else {
        // Continue other events
        ContinueDebugEvent(evt.processId, evt.threadId, DBG.CONTINUE);
      }
    }

    return null;
  }

  /** Set a hardware breakpoint using an available DR register */
  async setBreakpoint(
    pid: number,
    address: string,
    access: BreakpointAccess,
    size: BreakpointSize = 4,
  ): Promise<BreakpointConfig> {
    return (await setBreakpointShared({
      pid,
      address,
      access,
      size,
      ensureAttached: async (p) => {
        if (!this.attachedPids.has(p)) await this.attach(p);
      },
      allocateDR: () => this.allocateDR(),
      applyToAllThreads: (p, idx, addr, acc, sz, en) =>
        this.applyDRToAllThreads(p, idx, addr, acc, sz, en),
      register: (config) => this.breakpoints.set(config.id, config),
    })) as BreakpointConfig;
  }

  /** Remove a hardware breakpoint */
  async removeBreakpoint(id: string): Promise<boolean> {
    return removeBreakpointShared({
      id,
      breakpoints: this.breakpoints,
      clearDR: (pid, drIndex) => this.clearDR(pid, drIndex),
      drAllocation: this.drAllocation,
    });
  }

  /** Trace access: collect multiple hits, answers "who reads/writes this address?" */
  async traceAccess(
    pid: number,
    address: string,
    access: BreakpointAccess,
    maxHits?: number,
    timeoutMs?: number,
  ): Promise<BreakpointHit[]> {
    return traceAccessShared({
      pid,
      address,
      access,
      maxHits,
      timeoutMs,
      constants: { BREAKPOINT_TRACE_MAX_HITS, BREAKPOINT_HIT_TIMEOUT_MS },
      setBreakpoint: (p, a, acc) => this.setBreakpoint(p, a, acc),
      waitForHit: (ms) => this.waitForHit(ms),
      removeBreakpoint: (id) => this.removeBreakpoint(id),
    });
  }

  // ── Private ──

  private allocateDR(): number {
    // AMD64 has 4 hardware debug registers (DR0-3); Windows-on-ARM64 exposes
    // only 2 hardware watchpoints (Wvr0-1 / Wcr0-1).
    const maxSlots = IS_ARM64_WINDOWS ? 2 : 4;
    for (let i = 0; i < maxSlots; i++) {
      if (!this.drAllocation[i]) {
        this.drAllocation[i] = true;
        return i;
      }
    }
    throw new ToolError(
      'PREREQUISITE',
      IS_ARM64_WINDOWS
        ? 'All 2 hardware watchpoint registers (WVR0-1) are in use'
        : 'All 4 hardware breakpoint registers (DR0-DR3) are in use',
    );
  }

  // DR7 is rebuilt from this engine's active breakpoints for this pid only —
  // including other pids' breakpoints would pollute this process's debug state.
  private readonly applyDRToAllThreads = makeApplyDRAdapter((pid, idx, acc, sz, en) => {
    const entries: Dr7Entry[] = Array.from(this.breakpoints.values())
      .filter((bp) => bp.enabled && bp.pid === pid)
      .map((bp) => ({
        drIndex: bp.drIndex,
        enabled: true,
        access: DR_ACCESS_MAP[bp.access],
        size: bp.size,
      }));

    if (en) {
      entries.push({ drIndex: idx, enabled: true, access: DR_ACCESS_MAP[acc], size: sz });
    }
    return entries;
  });

  private clearDR(pid: number, drIndex: number): void {
    const dummyAccess: BreakpointAccess = 'write';
    this.applyDRToAllThreads(pid, drIndex, 0n, dummyAccess, 1, false);
  }

  private processHit(
    threadId: number,
    processId: number,
    _exceptionAddress?: bigint,
  ): BreakpointHit | null {
    // Find which breakpoint was hit by checking DR6
    let hThread: bigint;
    try {
      hThread = openThreadForDebug(threadId);
    } catch {
      return null;
    }

    try {
      const ctxBuf = GetThreadContext(hThread, CONTEXT_FLAGS.ALL);
      const ctx = parseContext(ctxBuf);

      // AMD64: DR6 bits 0-3 indicate which breakpoint was hit.
      // ARM64: no DR6; watchpoint faults don't tag the Wvr index in CONTEXT. With
      // only 2 watchpoints we match the ARM64 breakpoint whose address equals the
      // faulting address when the caller supplies it, else the first enabled one
      // for this pid. (Runtime semantics not exercisable on an x64 host.)
      for (const [id, bp] of this.breakpoints) {
        if (bp.pid !== processId) continue;

        let hit = false;
        if (IS_ARM64_WINDOWS) {
          const bpAddr = BigInt(bp.address.startsWith('0x') ? bp.address : `0x${bp.address}`);
          const addrHit = _exceptionAddress !== undefined && _exceptionAddress === bpAddr;
          hit = addrHit || bp.enabled;
          if (!addrHit && bp.enabled) {
            // Prefer a breakpoint whose address matches the reported faulting address;
            // only fall back to any-enabled when there is exactly one enabled.
            const enabled = Array.from(this.breakpoints.values()).filter(
              (b) => b.pid === processId && b.enabled,
            );
            if (enabled.length !== 1) continue;
          }
        } else {
          const drBit = 1n << BigInt(bp.drIndex);
          hit = (ctx.dr6 & drBit) !== 0n;
        }
        if (!hit) continue;

        bp.hitCount++;
        bp.lastHit = Date.now();

        // Clear debug-register hit state (DR6 on AMD64; no-op on ARM64).
        if (!IS_ARM64_WINDOWS) {
          ctxBuf.writeBigUInt64LE(0n, 0x68);
        }
        SetThreadContext(hThread, ctxBuf);

        return {
          breakpointId: id,
          address: bp.address,
          accessAddress: bp.address,
          instructionAddress: toHex(ctx.rip),
          threadId,
          accessType: bp.access,
          timestamp: Date.now(),
          registers: {
            rax: toHex(ctx.rax),
            rbx: toHex(ctx.rbx),
            rcx: toHex(ctx.rcx),
            rdx: toHex(ctx.rdx),
            rsi: toHex(ctx.rsi),
            rdi: toHex(ctx.rdi),
            rsp: toHex(ctx.rsp),
            rbp: toHex(ctx.rbp),
            r8: toHex(ctx.r8),
            r9: toHex(ctx.r9),
            r10: toHex(ctx.r10),
            r11: toHex(ctx.r11),
            r12: toHex(ctx.r12),
            r13: toHex(ctx.r13),
            r14: toHex(ctx.r14),
            r15: toHex(ctx.r15),
            rip: toHex(ctx.rip),
            rflags: `0x${ctx.eflags.toString(16).toUpperCase()}`,
          },
        };
      }

      return null;
    } finally {
      CloseHandle(hThread);
    }
  }
}

export const hardwareBreakpointEngine = new HardwareBreakpointEngine();

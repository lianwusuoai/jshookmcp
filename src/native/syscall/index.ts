export {
  ntOpenProcess,
  ntReadVirtualMemory,
  ntWriteVirtualMemory,
  ntAllocateVirtualMemory,
  ntProtectVirtualMemory,
  ntFreeVirtualMemory,
} from './DirectNtApi';
export { resolveNtdll, resetNtdllCache, resolveRuntimeKernelBase } from './SyscallResolver';
export type { SyscallEntry } from './SyscallResolver';
export { createScanWalker } from './ScanObfuscator';

export { enumerateKernelModules, findKernelModule } from './NtModuleEnumerator';

// ── InProcessPatcher ─────────────────────────────────────────────────────────

// ── ChaosScanner ─────────────────────────────────────────────────────────────

// ── KernelCallbackDetector ───────────────────────────────────────────────────

// ── InstrumentationCallbackDetector ──────────────────────────────────────────

// ── ProcessMasquerade ────────────────────────────────────────────────────────

// ── SelfDefense ──────────────────────────────────────────────────────────────

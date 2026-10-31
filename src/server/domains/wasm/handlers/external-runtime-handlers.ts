import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import {
  argNumber,
  argString,
  argStringArray,
  argStringRequired,
} from '@server/domains/shared/parse-args';
import { WASM_OPTIMIZE_TIMEOUT_MS } from '@src/constants';
import { ExternalToolHandlersBase } from './external-base';

export class ExternalRuntimeHandlers extends ExternalToolHandlersBase {
  async handleWasmOfflineRun(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const functionName = argStringRequired(args, 'functionName');
    const fnArgs = argStringArray(args, 'args');
    const runtime = argString(args, 'runtime', 'auto');
    const timeoutMs = argNumber(args, 'timeoutMs', 10_000);

    const numericArgs = fnArgs.map((a) => {
      const n = Number(a);
      return Number.isFinite(n) ? n : 0;
    });

    // 'node' forces the built-in WebAssembly runtime (zero install, sandboxed by the
    // engine). 'auto' prefers wasmtime/wasmer and falls back to it when neither
    // external runtime is installed, instead of hard-failing.
    if (runtime === 'node' || runtime === 'auto') {
      if (runtime === 'auto') {
        const probes = await this.state.runner.probeAll();
        if (probes['runtime.wasmtime']?.available || probes['runtime.wasmer']?.available) {
          const external = await this.runExternalRuntime(
            probes['runtime.wasmtime']?.available ? 'runtime.wasmtime' : 'runtime.wasmer',
            inputPath,
            functionName,
            fnArgs,
            timeoutMs,
          );
          if (external !== null) return external;
        } else {
          const nodeResult = await this.runNodeWasm(inputPath, functionName, numericArgs);
          if (nodeResult !== null) return nodeResult;
          return this.fail(
            'No WASM runtime found. Install wasmtime or wasmer, or pass runtime=node for the built-in WebAssembly engine.',
          );
        }
      } else {
        const nodeResult = await this.runNodeWasm(inputPath, functionName, numericArgs);
        if (nodeResult !== null) return nodeResult;
      }
    }

    const toolName: 'runtime.wasmtime' | 'runtime.wasmer' =
      runtime === 'wasmer' ? 'runtime.wasmer' : 'runtime.wasmtime';
    const external = await this.runExternalRuntime(
      toolName,
      inputPath,
      functionName,
      fnArgs,
      timeoutMs,
    );
    if (external !== null) return external;
    return this.fail(`runtime ${toolName} failed`);
  }

  private async runExternalRuntime(
    toolName: 'runtime.wasmtime' | 'runtime.wasmer',
    inputPath: string,
    functionName: string,
    fnArgs: string[],
    timeoutMs: number,
  ): Promise<Record<string, unknown> | null> {
    const runArgs =
      toolName === 'runtime.wasmtime'
        ? ['run', '--invoke', functionName, inputPath, ...fnArgs]
        : ['run', inputPath, '--invoke', functionName, '--', ...fnArgs];

    const result = await this.state.runner.run({
      tool: toolName,
      args: runArgs,
      timeoutMs,
      requireNonEmptyOutput: true,
      outputLabel: 'runtime output',
    });
    // Runtime absence (binary not installed) → caller falls back. A genuine
    // execution failure (bad function name, module error) must surface its stderr.
    if (!result.ok && /enoent|spawn/i.test(result.stderr)) return null;

    return this.ok({
      runtime: toolName,
      functionName,
      args: fnArgs,
      output: result.stdout.trim(),
      stderr: result.stderr.trim() || undefined,
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      success: result.ok,
    });
  }

  /**
   * Execute an exported function through Node's built-in WebAssembly engine.
   * Works for closed modules (no imports); imported modules fail with a clear
   * LinkError so callers know to install wasmtime/wasmer instead.
   */
  private async runNodeWasm(
    inputPath: string,
    functionName: string,
    numericArgs: number[],
  ): Promise<Record<string, unknown> | null> {
    const start = performance.now();
    try {
      const bytes = await readFile(inputPath);
      const compiled = await WebAssembly.instantiate(bytes, {});
      const fn = compiled.instance.exports[functionName];
      if (typeof fn !== 'function') {
        return this.fail(
          `Export "${functionName}" not found or not callable. Exports: ${Object.keys(compiled.instance.exports).join(', ') || '(none)'}`,
        );
      }
      const output = (fn as (...a: number[]) => unknown)(...numericArgs);
      return this.ok({
        runtime: 'node (built-in WebAssembly)',
        functionName,
        args: numericArgs.map(String),
        output: String(output),
        exitCode: 0,
        durationMs: performance.now() - start,
        success: true,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Compile/Link errors mean the module needs more than the bare engine can
      // offer — surface them as the tool result rather than falling through.
      return this.fail(`node WebAssembly runtime: ${message}`);
    }
  }

  async handleWasmOptimize(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const outputPath = argString(args, 'outputPath');
    const level = argString(args, 'level', 'O2');
    const destPath = await this.resolveArtifactOutputPath({
      outputPath,
      artifact: {
        category: 'wasm',
        toolName: 'wasm-opt',
        ext: 'wasm',
      },
      pathMode: 'absolute',
    });

    const result = await this.state.runner.run({
      tool: 'binaryen.wasm-opt',
      args: [`-${level}`, inputPath, '-o', destPath],
      timeoutMs: WASM_OPTIMIZE_TIMEOUT_MS,
      expectedOutputPaths: [destPath],
      outputLabel: 'optimized wasm',
    });

    if (!result.ok) {
      return this.fail(result.stderr, result.exitCode ?? undefined);
    }

    const inputSize = await this.tryStatSize(inputPath);
    const outputSize = await this.tryStatSize(destPath);

    return this.ok({
      artifactPath: destPath,
      optimizationLevel: level,
      inputSizeBytes: inputSize,
      outputSizeBytes: outputSize,
      reductionPercent: inputSize > 0 ? ((1 - outputSize / inputSize) * 100).toFixed(1) : '0',
      durationMs: result.durationMs,
    });
  }
}

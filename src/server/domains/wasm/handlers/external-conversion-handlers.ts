import { mkdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { argBool, argString, argStringRequired } from '@server/domains/shared/parse-args';
import { WASM_TOOL_TIMEOUT_MS } from '@src/constants';
import { ExternalToolHandlersBase } from './external-base';
import { inspectModuleStructure } from './module-structure';

export class ExternalConversionHandlers extends ExternalToolHandlersBase {
  async handleWasmDisassemble(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const outputPath = argString(args, 'outputPath');
    const foldExprs = argBool(args, 'foldExprs', true);

    const toolArgs = [inputPath, '-o', '/dev/stdout'];
    if (foldExprs) {
      toolArgs.push('--fold-exprs');
    }

    const result = await this.state.runner.run({
      tool: 'wabt.wasm2wat',
      args: toolArgs,
      timeoutMs: WASM_TOOL_TIMEOUT_MS,
      requireNonEmptyOutput: true,
      outputLabel: 'wasm text output',
    });

    if (!result.ok) {
      return this.fail(result.stderr, result.exitCode ?? undefined);
    }

    const savedPath = await this.writeTextArtifact({
      outputPath,
      artifact: {
        category: 'wasm',
        toolName: 'wasm-disassemble',
        ext: 'wat',
      },
      content: result.stdout,
    });

    return this.ok({
      artifactPath: savedPath,
      totalLines: result.stdout.split('\n').length,
      sizeBytes: result.stdout.length,
      preview: this.preview(result.stdout, 50),
      durationMs: result.durationMs,
    });
  }

  async handleWasmDecompile(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const outputPath = argString(args, 'outputPath');

    const result = await this.state.runner.run({
      tool: 'wabt.wasm-decompile',
      args: [inputPath, '-o', '/dev/stdout'],
      timeoutMs: WASM_TOOL_TIMEOUT_MS,
      requireNonEmptyOutput: true,
      outputLabel: 'wasm decompile output',
    });

    if (!result.ok) {
      return this.fail(result.stderr, result.exitCode ?? undefined);
    }

    const savedPath = await this.writeTextArtifact({
      outputPath,
      artifact: {
        category: 'wasm',
        toolName: 'wasm-decompile',
        ext: 'dcmp',
      },
      content: result.stdout,
    });

    return this.ok({
      artifactPath: savedPath,
      totalLines: result.stdout.split('\n').length,
      preview: this.preview(result.stdout, 60),
      durationMs: result.durationMs,
    });
  }

  async handleWasmInspectSections(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const sections = argString(args, 'sections', 'details');

    const flagMap: Record<string, string> = {
      headers: '-h',
      details: '-x',
      disassemble: '-d',
      all: '-h -x -d',
    };

    const flags = (flagMap[sections] || '-x').split(' ');
    const result = await this.state.runner.run({
      tool: 'wabt.wasm-objdump',
      args: [...flags, inputPath],
      timeoutMs: WASM_TOOL_TIMEOUT_MS,
      requireNonEmptyOutput: true,
      outputLabel: 'wasm section dump',
    });

    if (!result.ok) {
      // wabt absent or broken: fall back to the pure-TS structural parser instead of
      // hard-failing. The pure path covers section identity/sizes (no disassembly),
      // so disassemble requests that cannot be served stay a loud failure.
      const wabtUnavailable = /wasm-objdump|enoent|spawn|not found|which/i.test(result.stderr);
      if (!wabtUnavailable || sections === 'disassemble') {
        return this.fail(result.stderr, result.exitCode ?? undefined);
      }
      let bytes: Buffer;
      let structure: ReturnType<typeof inspectModuleStructure>;
      try {
        bytes = await readFile(inputPath);
        structure = inspectModuleStructure(bytes);
      } catch (fallbackError) {
        // The file itself is unreadable — surface BOTH the wabt error and the
        // fallback error so neither diagnostic path is hidden.
        const fallbackMessage =
          fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
        return this.fail(
          `${result.stderr.trim()} (pure-TS fallback also failed: ${fallbackMessage})`,
        );
      }
      // Project the parsed structure onto a section list equivalent to objdump -h:
      // every standard section the parser observed (count>0) plus custom sections.
      const fallbackSections: Array<Record<string, unknown>> = [
        { name: 'type', id: 1, count: structure.types.length },
        { name: 'import', id: 2, count: structure.importCount },
        { name: 'function', id: 3, count: structure.declaredFunctions.length },
        { name: 'table', id: 4, count: structure.tables.length },
        { name: 'memory', id: 5, count: structure.memories.length },
        { name: 'global', id: 6, count: structure.globals.length },
        { name: 'export', id: 7, count: structure.exportCount },
        ...(structure.startFunction !== undefined ? [{ name: 'start', id: 8, count: 1 }] : []),
        { name: 'element', id: 9, count: structure.elementSegments },
        ...(structure.codeSection
          ? [
              {
                name: 'code',
                id: 10,
                count: structure.codeSection.functionCount,
                bytes: structure.codeSection.totalCodeBytes,
              },
            ]
          : []),
        { name: 'data', id: 11, count: structure.dataSegments },
        ...structure.customSections.map((c) => ({
          name: `custom:${c.name}`,
          bytes: c.payloadBytes,
        })),
      ];
      return this.ok({
        source: 'pure-ts-fallback',
        reason: `wabt wasm-objdump unavailable (${result.stderr.trim().split('\n')[0] ?? 'unknown'})`,
        totalLines: fallbackSections.length,
        preview: fallbackSections
          .map(
            (sec) =>
              `${String(sec['name'])}: ${String(sec['bytes'] ?? `${String(sec['count'])} entries`)}`,
          )
          .join('\n'),
        sections: fallbackSections,
        parseErrors: structure.parseErrors,
        durationMs: result.durationMs,
      });
    }

    return this.ok({
      totalLines: result.stdout.split('\n').length,
      preview: this.preview(result.stdout, 100),
      durationMs: result.durationMs,
    });
  }

  async handleWasmToC(args: Record<string, unknown>) {
    const inputPath = argStringRequired(args, 'inputPath');
    const outputDir = argString(args, 'outputDir');
    const destDir = await this.resolveArtifactOutputPath({
      outputPath: outputDir,
      artifact: {
        category: 'wasm',
        toolName: 'wasm2c',
        ext: 'dir',
      },
      pathMode: 'absolute',
    });

    await mkdir(destDir, { recursive: true });

    const baseName = resolve(inputPath).replace(/\.wasm$/i, '');
    const nameOnly = baseName.split(/[/\\]/).pop() || 'output';
    const cFile = join(destDir, `${nameOnly}.c`);
    const hFile = join(destDir, `${nameOnly}.h`);

    const result = await this.state.runner.run({
      tool: 'wabt.wasm2c',
      args: [inputPath, '-o', cFile],
      timeoutMs: WASM_TOOL_TIMEOUT_MS,
      expectedOutputPaths: [cFile, hFile],
      outputLabel: 'wasm2c output',
    });

    if (!result.ok) {
      return this.fail(result.stderr, result.exitCode ?? undefined);
    }

    return this.ok({
      outputDir: destDir,
      cFile,
      hFile,
      cSizeBytes: await this.tryStatSize(cFile),
      hSizeBytes: await this.tryStatSize(hFile),
      durationMs: result.durationMs,
    });
  }
}

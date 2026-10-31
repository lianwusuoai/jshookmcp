import { argString, argNumber } from '@server/domains/shared/parse-args';
import { PAGE_EVALUATE_TIMEOUT_MS } from '@src/constants';
import { PrerequisiteError } from '@errors/PrerequisiteError';
import { R } from '@server/domains/shared/ResponseBuilder';
import type { ToolResponse } from '@server/domains/shared/ResponseBuilder';
import { extractFrameworkState } from './framework-state.template';

/** How long the pre-flight CDP health check may take before the debugger is
 *  considered to be blocking page evaluation. */
const CDP_HEALTH_CHECK_TIMEOUT_MS = 3000;

interface EvaluatablePage {
  evaluate(pageFunction: unknown, ...args: unknown[]): Promise<unknown>;
  createCDPSession(): Promise<{
    send(method: string, params?: Record<string, unknown>): Promise<unknown>;
    detach?(): Promise<unknown>;
  }>;
}

interface FrameworkStateHandlersDeps {
  getActivePage: () => Promise<unknown>;
}

export class FrameworkStateHandlers {
  private deps: FrameworkStateHandlersDeps;
  constructor(deps: FrameworkStateHandlersDeps) {
    this.deps = deps;
  }

  async handleFrameworkStateExtract(args: Record<string, unknown>): Promise<ToolResponse> {
    const framework = argString(args, 'framework', 'auto');
    const selector = argString(args, 'selector', '');
    const maxDepth = argNumber(args, 'maxDepth', 5);

    try {
      const page = (await this.deps.getActivePage()) as EvaluatablePage;

      // Pre-flight CDP health check: verify the page's CDP target is responsive.
      try {
        const cdp = await page.createCDPSession();
        try {
          await Promise.race([
            cdp.send('Runtime.evaluate', { expression: '1', returnByValue: true }),
            new Promise<never>((_, reject) =>
              setTimeout(() => reject(new Error('cdp_unreachable')), CDP_HEALTH_CHECK_TIMEOUT_MS),
            ),
          ]);
        } finally {
          // Release the probe session so repeated calls do not leak CDP sessions.
          await cdp.detach?.().catch(() => {});
        }
      } catch {
        throw new PrerequisiteError(
          'CDP session unresponsive — the debugger may be blocking page evaluation. ' +
            "Call debugger_lifecycle({ action: 'disable' })() before framework_state_extract, or run it before " +
            "debugger_lifecycle({ action: 'enable' }).",
        );
      }

      // Wrap with 30s timeout to avoid hanging when CDP session is stale
      const evalPromise = page.evaluate(extractFrameworkState, { framework, selector, maxDepth });

      const result = (await Promise.race([
        evalPromise,
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error(`page.evaluate timed out after ${PAGE_EVALUATE_TIMEOUT_MS}ms`)),
            PAGE_EVALUATE_TIMEOUT_MS,
          ),
        ),
      ])) as Record<string, unknown>;

      return R.ok().build(result);
    } catch (error) {
      return R.fail(error).build();
    }
  }
}

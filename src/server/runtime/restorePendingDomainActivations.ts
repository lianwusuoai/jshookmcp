/**
 * Startup restore for domains that were active in a previous session.
 *
 * Deliberately a leaf module: it statically depends only on ServerRuntimeState
 * and reaches the activate_domain handler through a lazy dynamic import.
 * Putting this in either ServerRuntimeState (state layer reaching into the
 * handler layer) or MCPServer.search.handlers.domain (whose static import
 * chain, once pulled in by MCPServer.ts, fans the registry/manifest graph
 * back into every search shard) wires a hub cycle — fallow measured both
 * variants at +11 circular dependencies.
 */
import { logger } from '@utils/logger';
import type { MCPServerContext } from '@server/MCPServer.context';
import { getRuntimeState } from '@server/runtime/ServerRuntimeState';

export async function restorePendingDomainActivations(ctx: MCPServerContext): Promise<void> {
  const runtimeState = getRuntimeState(ctx);
  if (!runtimeState) {
    return;
  }

  const pendingDomains = runtimeState.getPendingActivatedDomains();
  if (pendingDomains.length === 0) {
    return;
  }

  for (const domain of pendingDomains) {
    if (ctx.enabledDomains.has(domain) && ctx.domainTtlEntries.has(domain)) {
      continue;
    }

    try {
      const { handleActivateDomain } = await import('@server/MCPServer.search.handlers.domain');
      const ttlEntry = runtimeState.getPendingDomainTtl(domain);
      await handleActivateDomain(ctx, {
        domain,
        ...(ttlEntry ? { ttlMinutes: ttlEntry.ttlMinutes } : {}),
      });
    } catch (error) {
      logger.warn(`Failed to restore activated domain "${domain}":`, error);
    }
  }
}

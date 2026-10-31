/**
 * Profile-tier view over build-time domain metadata.
 *
 * Split out of `registry/views.ts` so the views module (imported by
 * ToolCatalog, whose import graph the cycle audit traced back into every
 * domain manifest) does not need `generated-domains.js` — the only reason
 * views depended on it was this builder's DOMAIN_PROFILE_MAP lookup.
 */
import type { ToolProfileId } from '@server/registry/contracts';
import { DOMAIN_PROFILE_MAP } from '@server/registry/generated-domains.js';
import { logger } from '@utils/logger';

function isSubset(a: string[], b: string[]): boolean {
  const bSet = new Set(b);
  return a.every((x) => bSet.has(x));
}

export function buildProfileDomains(): Record<ToolProfileId, string[]> {
  const profiles: Record<string, Set<string>> = {
    search: new Set(),
    workflow: new Set(),
    full: new Set(),
  };

  // Use build-time metadata as single source of truth — works even when
  // manifests haven't been loaded yet (search profile starts with 0 loaded).
  for (const [domain, domainProfiles] of Object.entries(DOMAIN_PROFILE_MAP)) {
    for (const p of domainProfiles) {
      profiles[p]?.add(domain);
    }
  }

  const result: Record<string, string[]> = {};
  for (const [p, domains] of Object.entries(profiles)) {
    result[p] = [...(domains as Set<string>)];
  }

  // Validate tier hierarchy
  if (!isSubset(result['search']!, result['workflow']!)) {
    logger.warn('[registry] Profile hierarchy: search not subset of workflow');
  }
  if (!isSubset(result['workflow']!, result['full']!)) {
    logger.warn('[registry] Profile hierarchy: workflow not subset of full');
  }

  return result as Record<ToolProfileId, string[]>;
}

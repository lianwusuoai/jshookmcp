/**
 * Registry state — the manifest/registration caches and the invalidation
 * listener registry, extracted from `registry/index.ts`.
 *
 * Consumers that only need read access to the loaded manifests
 * (`ToolRouter.policy`, `ToolRouter.intent`) import this leaf module instead
 * of the `registry/index` barrel. The barrel's import graph reaches every
 * domain manifest via `discovery.ts` → `generated-domains.ts`, so a static
 * dependency on it from router-layer modules re-creates the registry↔router
 * cycle family (see the ToolRouter/Workflow cycles this module broke).
 *
 * Writers (`initRegistry`, `ensureDomainLoaded`) stay in `registry/index.ts`
 * and mutate the caches here through the exported setters.
 */
import type { DomainManifest, ToolRegistration } from '@server/registry/contracts';

let manifestsCache: DomainManifest[] | null = null;
let registrationsCache: ToolRegistration[] | null = null;

const invalidationListeners: Array<() => void> = [];

/** Subscribe a callback to be invoked whenever registry state changes in a way that invalidates derived caches. */
export function onRegistryInvalidate(listener: () => void): void {
  invalidationListeners.push(listener);
}

export function notifyRegistryInvalidation(): void {
  for (const listener of invalidationListeners) listener();
}

/** Read access to the loaded manifests. Throws before initRegistry(). */
export function getLoadedManifests(): readonly DomainManifest[] {
  if (!manifestsCache) throw new Error('[registry] Not initialised - call initRegistry() first.');
  return manifestsCache;
}

/** Read access to the loaded registrations. Throws before initRegistry(). */
export function getLoadedRegistrations(): readonly ToolRegistration[] {
  if (!registrationsCache)
    throw new Error('[registry] Not initialised - call initRegistry() first.');
  return registrationsCache;
}

// ── writer API (registry/index.ts only) ──

/** Initialize the caches after discovery. Internal to the registry. */
export function setRegistryCaches(
  manifests: DomainManifest[],
  registrations: ToolRegistration[],
): void {
  manifestsCache = manifests;
  registrationsCache = registrations;
}

/** Whether initRegistry() has completed. */
export function isRegistryInitialised(): boolean {
  return manifestsCache !== null;
}

/** Register one manifest loaded on demand; returns the mutable manifests array. */
export function pushLoadedManifest(manifest: DomainManifest): DomainManifest[] {
  if (!manifestsCache) throw new Error('[registry] Not initialised - call initRegistry() first.');
  manifestsCache.push(manifest);
  return manifestsCache;
}

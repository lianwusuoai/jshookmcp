import { describe, expect, it } from 'vitest';
import { META_TOOL_NAMES } from '@server/MCPServer.search.meta-names';

/**
 * META_TOOL_DEFINITIONS in MCPServer.search.ts is the authoring source; this
 * leaf module mirrors the names so guard/handler consumers can avoid the
 * barrel. Both are static lists, so drift protection is a plain cross-check:
 * if a meta tool is added to one and not the other, this fails.
 */
describe('MCPServer.search.meta-names', () => {
  it('contains exactly the 8 canonical meta tools', () => {
    expect(META_TOOL_NAMES).toEqual(
      new Set([
        'search_tools',
        'route_tool',
        'describe_tool',
        'activate_tools',
        'deactivate_tools',
        'activate_domain',
        'call_tool',
        'coverage_report',
      ]),
    );
  });

  it('matches the names registered by META_TOOL_DEFINITIONS in the barrel', async () => {
    // The barrel derives META_TOOL_NAMES from META_TOOL_DEFINITIONS via the
    // re-export; importing the barrel here is safe from tests.
    const { getMetaToolHandler } = await import('@server/MCPServer.search');
    for (const name of META_TOOL_NAMES) {
      expect(getMetaToolHandler(name), `handler registered for ${name}`).toBeDefined();
    }
  });
});

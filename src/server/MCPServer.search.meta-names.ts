/**
 * Canonical meta-tool names.
 *
 * Extracted from `MCPServer.search.ts` so that consumers that only need the
 * name set — `ToolCallContextGuard` (repeat-guard excludes) and the search
 * handler modules' dynamic imports — can depend on this leaf module instead
 * of the barrel, which registers the handlers defined in those same modules
 * and therefore must not be imported by them (see the cycles this broke).
 *
 * Keep the list in sync with `META_TOOL_DEFINITIONS` in `MCPServer.search.ts`;
 * `tests/server/MCPServer.search.meta-names.test.ts` cross-checks the two.
 */
export const META_TOOL_NAMES: ReadonlySet<string> = new Set([
  'search_tools',
  'route_tool',
  'describe_tool',
  'activate_tools',
  'deactivate_tools',
  'activate_domain',
  'call_tool',
  'coverage_report',
]);

/**
 * Browser Module Exports
 *
 * This module provides unified browser management capabilities supporting:
 * - Chrome (via rebrowser-puppeteer-core)
 * - Camoufox (Firefox via camoufox-js)
 */

// Unified Browser Manager (primary interface)
export { UnifiedBrowserManager } from '@modules/browser/UnifiedBrowserManager';

// Chrome Browser Manager
export { BrowserModeManager } from '@modules/browser/BrowserModeManager';

// Camoufox Browser Manager
export { CamoufoxBrowserManager } from '@modules/browser/CamoufoxBrowserManager';

// Browser Discovery
export { BrowserDiscovery } from '@modules/browser/BrowserDiscovery';

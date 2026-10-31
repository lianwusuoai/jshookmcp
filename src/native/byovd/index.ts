export { byovdManager } from './ByovdManager';
export * from './types';
export { byovdDriverRegistry } from './drivers';
export { KernelCallbackManager } from './KernelCallbackManager';
export type { CallbackRestorePoint } from './KernelCallbackManager';
export {
  Hypervisor,
  getHypervisor,
  resetHypervisorForTest,
  adjustControlField,
  computeAdjustedControls,
  initVmxonRegion,
  buildEptIdentityTables,
  configureMsrBitmap,
  computeMsrBitmapPosition,
  INTERCEPTED_MSRS,
} from './Hypervisor';
export { encodeEptPte, encodeVmcsField, decodeVmcsField } from './VmxConstants';
export type { PhysicalAllocation, VmxCapabilityMsrs } from './Hypervisor.types';

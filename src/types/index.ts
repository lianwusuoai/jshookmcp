export type { Config, PuppeteerConfig, CacheConfig } from '@internal-types/config';

export type {
  CollectCodeOptions,
  CodeFile,
  CollectCodeResult,
  DependencyGraph,
} from '@internal-types/collector';
export type {
  ObfuscationType,
  ObfuscationClassifier,
  DeobfuscateOptions,
  DeobfuscateResult,
} from '@internal-types/deobfuscator';
export type {
  UnderstandCodeOptions,
  UnderstandCodeResult,
  CodeStructure,
  TechStack,
  BusinessLogic,
  DataFlow,
  SecurityRisk,
  FunctionInfo,
  ClassInfo,
  CallGraph,
} from '@internal-types/analysis';
export type {
  DetectCryptoOptions,
  DetectCryptoResult,
  CryptoAlgorithm,
  CryptoLibrary,
} from '@internal-types/crypto';
export type { HookOptions, HookContext, HookResult, HookRecord } from '@internal-types/hook';
export type {
  ScopeVariable,
  BreakpointHitEvent,
  BreakpointHitCallback,
  DebuggerSession,
  GetScopeVariablesOptions,
  GetScopeVariablesResult,
} from '@internal-types/debugger';
export type {
  DetectedEnvironmentVariables,
  MissingAPI,
  EmulationCode,
  EnvironmentEmulatorOptions,
  EnvironmentEmulatorResult,
} from '@internal-types/emulator';
export type {
  VMType,
  ComplexityLevel,
  VMInstruction,
  VMFeatures,
  UnresolvedPart,
  JSVMPDeobfuscatorOptions,
  JSVMPDeobfuscatorResult,
} from '@internal-types/vm';

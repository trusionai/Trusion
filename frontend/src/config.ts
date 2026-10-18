/** Public build-time configuration. Contains NO secrets by construction: build.mjs only injects these three public values. */
export interface PublicConfig { apiBaseUrl: string; authUrl: string; authPublicKey: string }
declare const __TRUSION_CONFIG__: PublicConfig | undefined;
let override: PublicConfig | null = null;
export const setConfigForTests = (c: PublicConfig | null) => { override = c; };
export function getConfig(): PublicConfig {
  if (override) return override;
  if (typeof __TRUSION_CONFIG__ !== 'undefined' && __TRUSION_CONFIG__) return __TRUSION_CONFIG__;
  return { apiBaseUrl: '', authUrl: '', authPublicKey: '' };
}

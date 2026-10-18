import type { ModelSpec, Capability, Tier } from './types.ts';

const CAPS = new Set<Capability>(['text', 'vision', 'audio', 'json']);
const TIERS = new Set<Tier>(['free', 'paid', 'local']);

/**
 * Validate a model registry loaded from operator-controlled config (never from clients).
 * Throws on malformed entries so a typo cannot silently enable a model.
 */
export function parseRegistry(input: unknown): ModelSpec[] {
  if (!Array.isArray(input)) throw new Error('model registry must be an array');
  return input.map((m: any, i) => {
    const where = `registry[${i}]`;
    const bad = (msg: string) => new Error(`${where}: ${msg}`);
    if (typeof m?.id !== 'string' || !m.id) throw bad('id required');
    if (typeof m.provider !== 'string' || !m.provider) throw bad('provider required');
    if (!TIERS.has(m.tier)) throw bad('tier must be free|paid|local');
    if (!Array.isArray(m.capabilities) || !m.capabilities.every((c: any) => CAPS.has(c))) throw bad('invalid capabilities');
    for (const k of ['maxContextTokens', 'maxOutputTokens', 'qualityRank']) if (!Number.isFinite(m[k]) || m[k] < 0) throw bad(`${k} must be a non-negative number`);
    for (const k of ['priceInPerM', 'priceOutPerM']) if (m[k] !== null && !(Number.isFinite(m[k]) && m[k] >= 0)) throw bad(`${k} must be null or >= 0`);
    if (m.priceVerifiedAt !== null && Number.isNaN(Date.parse(m.priceVerifiedAt))) throw bad('priceVerifiedAt must be an ISO date or null');
    if (m.tier === 'paid' && (m.priceInPerM === null || m.priceOutPerM === null)) throw bad('paid models need explicit prices');
    if (!['external_logged', 'external_no_train', 'local'].includes(m.dataPolicy)) throw bad('invalid dataPolicy');
    return { ...m, enabled: m.enabled === true } as ModelSpec;
  });
}

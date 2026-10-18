import { createContext, useContext, useMemo, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import { createApiClient } from './api/client.ts';
import type { ApiClient } from './api/client.ts';
import { createGoTrueAuth } from './auth/gotrue.ts';
import { SessionManager } from './auth/session.ts';
import { getConfig } from './config.ts';

interface Ctx { sm: SessionManager; api: ApiClient; status: 'signedOut' | 'signedIn' }
const C = createContext<Ctx | null>(null);
export function AppProvider({ children, sm: injected, api: injectedApi }: { children: ReactNode; sm?: SessionManager; api?: ApiClient }) {
  const value = useMemo(() => {
    const cfg = getConfig();
    const sm = injected ?? new SessionManager(createGoTrueAuth({ baseUrl: cfg.authUrl, publicKey: cfg.authPublicKey }));
    const api = injectedApi ?? createApiClient({ baseUrl: cfg.apiBaseUrl, getToken: sm.getToken, onUnauthorized: () => { if (sm.status === 'signedIn') sm.expire('Your session expired. Please sign in again.'); } });
    return { sm, api };
  }, []);
  const status = useSyncExternalStore(value.sm.subscribe, () => value.sm.status);
  return <C.Provider value={{ ...value, status }}>{children}</C.Provider>;
}
export function useApp(): Ctx { const c = useContext(C); if (!c) throw new Error('AppProvider missing'); return c; }

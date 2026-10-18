export type RouteId = 'dashboard' | 'message' | 'url' | 'apk' | 'screenshot' | 'history' | 'account' | 'admin' | 'unavailable';
export interface Route { id: RouteId; param?: string }
export function parseHash(hash: string): Route {
  const h = hash.replace(/^#\/?/, '').split('?')[0];
  const [first, second] = h.split('/');
  switch (first) {
    case '': case 'dashboard': return { id: 'dashboard' };
    case 'message': case 'url': case 'apk': case 'screenshot': case 'account': case 'admin': return { id: first };
    case 'history': return { id: 'history', param: second ? decodeURIComponent(second).slice(0, 64) : undefined };
    case 'n': return { id: 'unavailable', param: second ? decodeURIComponent(second).slice(0, 64) : undefined };
    default: return { id: 'dashboard' };
  }
}

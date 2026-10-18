/**
 * Framework-free session manager. The access/refresh tokens live ONLY in this object's memory:
 * nothing is written to localStorage/sessionStorage/cookies, so a page reload signs the user out
 * (deliberate trade-off: no persisted token for XSS or a shared computer to steal).
 */
import { AuthFailure } from './gotrue.ts';
import type { AuthClient, AuthSession } from './gotrue.ts';

export type SessionStatus = 'signedOut' | 'signedIn';
export interface Scheduler { set(fn: () => void, ms: number): unknown; clear(h: unknown): void }
const realScheduler: Scheduler = { set: (fn, ms) => setTimeout(fn, ms), clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>) };

export class SessionManager {
  private session: AuthSession | null = null;
  private timer: unknown = null;
  private listeners = new Set<() => void>();
  notice: string | null = null;
  private auth: AuthClient; private sched: Scheduler; private now: () => number; private skewMs: number;
  constructor(auth: AuthClient, o: { scheduler?: Scheduler; clock?: () => number; refreshSkewMs?: number } = {}) {
    this.auth = auth; this.sched = o.scheduler ?? realScheduler; this.now = o.clock ?? Date.now; this.skewMs = o.refreshSkewMs ?? 60_000;
  }
  get status(): SessionStatus { return this.session ? 'signedIn' : 'signedOut'; }
  get email(): string | undefined { return this.session?.email; }
  getToken = (): string | null => (this.session && this.session.expiresAt > this.now() ? this.session.accessToken : null);
  subscribe = (fn: () => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private emit() { for (const l of [...this.listeners]) l(); }
  private set(s: AuthSession | null) {
    if (this.timer) { this.sched.clear(this.timer); this.timer = null; }
    this.session = s;
    if (s?.refreshToken) this.timer = this.sched.set(() => { void this.refresh(); }, Math.max(1_000, s.expiresAt - this.now() - this.skewMs));
    this.emit();
  }
  async signIn(email: string, password: string): Promise<void> { this.notice = null; this.set(await this.auth.signIn(email, password)); }
  signUp = (email: string, password: string) => this.auth.signUp(email, password);
  recover = (email: string) => this.auth.recover(email);
  async refresh(): Promise<void> {
    const rt = this.session?.refreshToken; if (!rt) { this.expire('Your session ended. Please sign in again.'); return; }
    try { this.set(await this.auth.refresh(rt)); }
    catch (e) { if (e instanceof AuthFailure && (e.kind === 'network' || e.kind === 'unavailable')) { this.timer = this.sched.set(() => { void this.refresh(); }, 15_000); return; } this.expire('Your session expired. Please sign in again.'); }
  }
  /** Called when the backend answers 401 or refresh fails: drop everything. */
  expire(notice: string): void { this.notice = notice; this.set(null); }
  async signOut(): Promise<void> { const t = this.session?.accessToken; this.notice = null; this.set(null); if (t) await this.auth.signOut(t); }
}

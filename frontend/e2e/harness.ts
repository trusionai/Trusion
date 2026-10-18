/** Shared boot for additional E2E files: build -> mock auth -> real backend -> static server with production CSP -> Chromium. */
import { execFileSync } from 'node:child_process';
import { chromium } from 'playwright';
import type { Browser, Page } from 'playwright';
import { bootBackend } from '../tests/helpers/backend.ts';
import { bootMockAuth } from '../tests/helpers/mock-auth.ts';
import { serveDist } from './helpers.ts';

process.env.PLAYWRIGHT_BROWSERS_PATH ??= '/opt/pw-browsers';
export const PORTS = { API: 18090, AUTH: 18091, WEB: 18092 };
export const PW = 'correct-horse-1';
const ROOT = new URL('..', import.meta.url).pathname;

export async function startHarness(users: Record<string, { password: string; sub: string }>, admins: string[] = []) {
  execFileSync('node', ['build.mjs'], { cwd: ROOT, stdio: 'pipe', env: { PATH: process.env.PATH, TRUSION_API_BASE_URL: `http://127.0.0.1:${PORTS.API}`, TRUSION_AUTH_URL: `http://127.0.0.1:${PORTS.AUTH}/auth/v1`, TRUSION_AUTH_PUBLIC_KEY: 'public-anon-key-for-tests', TRUSION_ALLOW_INSECURE_DEV: '1' } as never });
  const auth = await bootMockAuth(users, { port: PORTS.AUTH });
  const backend = await bootBackend({ port: PORTS.API, corsOrigins: [`http://127.0.0.1:${PORTS.WEB}`], admins });
  const web = await serveDist(ROOT + 'dist', PORTS.WEB);
  const browser: Browser = await chromium.launch({ args: ['--no-sandbox'] });
  return { auth, backend, web, browser, stop: async () => { await browser.close(); await web.close(); await backend.close(); await auth.close(); } };
}
export async function signIn(page: Page, name: string) {
  await page.locator('#email').fill(`${name}@example.com`); await page.locator('#password').fill(PW);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.locator('h1', { hasText: 'Dashboard' }).waitFor({ timeout: 10000 }); await page.locator('text=Plan:').waitFor();
}

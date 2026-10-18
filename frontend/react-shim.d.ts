// OFFLINE-ONLY type shim: @types/react could not be installed (no network). It types the small part of React this app uses
// loosely, so `tsc` can still check the app's OWN logic. It does NOT validate React API usage like the real @types/react.
// With network, use `npm install` + `npm run typecheck` (tsconfig.json) instead.
declare module 'react' {
  export type ReactNode = any;
  export type Dispatch<A> = (a: A) => void;
  export type SetStateAction<S> = S | ((p: S) => S);
  export function useState<S>(init: S | (() => S)): [S, Dispatch<SetStateAction<S>>];
  export function useReducer<S, A>(r: (s: S, a: A) => S, init: S): [S, Dispatch<A>];
  export function useRef<T>(v: T): { current: T };
  export function useEffect(f: () => void | (() => void), d?: unknown[]): void;
  export function useCallback<T extends (...a: any[]) => any>(f: T, d: unknown[]): T;
  export function useMemo<T>(f: () => T, d: unknown[]): T;
  export interface Context<T> { Provider: (p: { value: T; children?: ReactNode }) => any }
  export function createContext<T>(d: T): Context<T>;
  export function useContext<T>(c: Context<T>): T;
  export function useSyncExternalStore<T>(sub: (cb: () => void) => () => void, get: () => T): T;
  export type FormEvent = { preventDefault(): void };
  export type ChangeEvent<T = any> = { target: T & { files?: FileList | null; value: string; checked: boolean } };
}
declare module 'react/jsx-runtime' { export const jsx: any; export const jsxs: any; export const Fragment: any }
declare module 'react-dom/client' { export function createRoot(el: Element): { render(n: any): void } }
declare module '*.css' { const x: string; export default x }
declare namespace JSX { interface IntrinsicElements { [k: string]: any } interface Element {} interface ElementChildrenAttribute { children: {} } }

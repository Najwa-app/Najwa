declare const __NAJWA_LOCAL_WEB__: boolean;
// Each entry point's vite config aliases this module to its own bridge.ts.
declare module 'najwa:bridge' {
  export function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
}

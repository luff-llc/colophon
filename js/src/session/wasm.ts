/**
 * The web05 wasm-bindgen exports (docs/bindings-05.md), loaded once, and the two rules of that boundary this layer
 * hides from an app: a record passed to a call is consumed by it (so a fresh one is built per call), and a record that
 * comes back is a wasm object to free (so it is copied into plain values and freed at once).
 */
import wasmInit, * as glue from '../../dist/wasm/colophon_wasm.js';

export { glue };
export type AccountEngine = glue.AccountEngine;
export type AccountAction = glue.AccountAction;

let initialization: Promise<void> | undefined;
/**
 * Loads the wasm module once. With no argument the module is read from beside the package (a file URL under Node and
 * Bun, `fetch` in a browser); a bundled app passes the module's URL, a `Response`, or its bytes.
 */
export function init(source?: URL | string | Response | BufferSource | WebAssembly.Module): Promise<void> {
  initialization ??= (async () => {
    if (source !== undefined) { await wasmInit({ module_or_path: source }); return; }
    const url = new URL('../../dist/wasm/colophon_wasm_bg.wasm', import.meta.url);
    if (url.protocol === 'file:') {
      // A variable import keeps the browser build free of Node modules.
      const nodeFS = 'node:fs/promises';
      const fs: { readFile(path: URL): Promise<Uint8Array<ArrayBuffer>> } = await import(nodeFS);
      await wasmInit({ module_or_path: await fs.readFile(url) });
    } else {
      await wasmInit({ module_or_path: url });
    }
  })();
  initialization.catch(() => { initialization = undefined; });
  return initialization;
}

/** The typed error of every engine call (`AccountFault` in the glue): a real `Error` with `kind`, `code`, `detail`, `reason`. */
export interface AccountFault extends Error { kind: string; code: string; detail: string; reason: string | undefined }
export function isAccountFault(error: unknown): error is AccountFault {
  return error instanceof Error && error.name === 'AccountFault' && typeof (error as Partial<AccountFault>).kind === 'string'
    && typeof (error as Partial<AccountFault>).code === 'string';
}
/** A fault this layer raises in the engine's own shape (a locked or discarded engine). */
export function makeFault(kind: string, code: string, detail: string, reason?: string): AccountFault {
  const error = new Error(detail) as AccountFault;
  error.name = 'AccountFault'; error.kind = kind; error.code = code; error.detail = detail; error.reason = reason;
  return error;
}

const camel = (name: string): string => name.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());

/**
 * Copies a record the glue returned (or a list of them) into plain values with camelCase names and frees the wasm
 * object. `u64`/`i64` stay `bigint`, bytes stay `Uint8Array`, an absent optional is `undefined`, enums stay the
 * glue's numbers.
 */
export function plain<T>(value: unknown): T { return convert(value) as T; }
function convert(value: unknown): unknown {
  if (value === null || value === undefined) return undefined;
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map(convert);
  if (typeof value === 'object' && typeof (value as { free?: unknown }).free === 'function') {
    const out: Record<string, unknown> = {};
    const prototype = Object.getPrototypeOf(value) as object;
    for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(prototype))) {
      if (typeof descriptor.get !== 'function' || name.startsWith('__')) continue;
      out[camel(name)] = convert(descriptor.get.call(value));
    }
    (value as { free(): void }).free();
    return out;
  }
  return value;
}

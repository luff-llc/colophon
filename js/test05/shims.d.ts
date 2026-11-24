// The few Bun and Node APIs the tests use, declared loosely so the tests are typechecked against the SDK's own types
// without adding `bun-types` or `@types/node` to the package. Only tests see this file.
declare module 'bun:test' {
  type Body = () => void | Promise<void>;
  export function test(name: string, body: Body, timeoutMs?: number): void;
  export function describe(name: string, body: () => void): void;
  export function beforeAll(body: Body): void;
  export function afterAll(body: Body): void;
  interface Matchers {
    toBe(expected: unknown): void; toEqual(expected: unknown): void; toBeInstanceOf(type: unknown): void; toContain(expected: unknown): void;
    toMatchObject(expected: object): void; toBeLessThan(n: number): void; toBeUndefined(): void; toThrow(expected?: unknown): void;
    toBeDefined(): void; toBeGreaterThan(n: number | bigint): void; toBeGreaterThanOrEqual(n: number | bigint): void; toBeLessThanOrEqual(n: number | bigint): void;
    not: Matchers; rejects: { [K in keyof Matchers]: Matchers[K] extends (...args: infer A) => void ? (...args: A) => Promise<void> : never };
  }
  export function expect(actual: unknown): Matchers;
}
declare module 'node:os' { export function tmpdir(): string; }
declare module 'node:fs' {
  export function mkdtempSync(prefix: string): string;
  export function utimesSync(path: string, atime: number, mtime: number): void;
  export function writeFileSync(path: string, data: string | Uint8Array): void;
  export function readFileSync(path: string, encoding: 'utf8'): string;
  export function readFileSync(path: string | URL): Uint8Array;
  export function readdirSync(path: string): string[];
  export function readdirSync(path: string, options: { withFileTypes: true }): { name: string; isDirectory(): boolean }[];
}
interface BunSubprocess { exited: Promise<number>; kill(signal?: string | number): void; stdout: ReadableStream<Uint8Array>; exitCode: number | null; stdin?: unknown }
interface BunServer { port: number | undefined; stop(force?: boolean): Promise<void> }
declare const Bun: {
  spawn(command: string[], options?: Record<string, unknown>): BunSubprocess;
  spawnSync(command: string[], options?: Record<string, unknown>): { exitCode: number; stderr: { toString(): string } };
  serve(options: { port: number; hostname: string; idleTimeout?: number; tls?: unknown; fetch(request: Request): Response | Promise<Response> }): BunServer;
  build(options: Record<string, unknown>): Promise<{ success: boolean; logs: unknown[] }>;
  file(path: string): Blob;
  sleep(ms: number): Promise<void>;
};
declare const process: {
  pid: number; execPath: string; argv: string[]; env: Record<string, string | undefined>;
  on(event: 'exit', listener: () => void): void; off(event: 'exit', listener: () => void): void;
  kill(pid: number, signal: string | number): boolean; exit(code: number): never;
};
interface ImportMeta { dir: string }

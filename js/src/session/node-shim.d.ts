// The few Node (and Bun) built-ins `node.ts` uses, declared here so the package needs no `@types/node`.
declare module 'node:fs' {
  interface Stats { size: number; mtimeMs: number; isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }
  interface Dirent { name: string; isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }
  export function mkdirSync(path: string, options?: { recursive?: boolean }): string | undefined;
  export function readFileSync(path: string): Uint8Array;
  export function openSync(path: string, flags: string, mode?: number): number;
  export function writeSync(fd: number, data: Uint8Array, offset?: number, length?: number): number;
  export function fsyncSync(fd: number): void;
  export function closeSync(fd: number): void;
  export function renameSync(from: string, to: string): void;
  export function linkSync(existing: string, path: string): void;
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  export function lstatSync(path: string): Stats;
  export function existsSync(path: string): boolean;
  export function realpathSync(path: string): string;
}
declare module 'node:path' {
  export function join(...parts: string[]): string;
  export function dirname(path: string): string;
  export const sep: string;
}
declare module 'node:crypto' {
  export function createHash(algorithm: 'sha256'): { update(data: Uint8Array): { digest(encoding: 'hex'): string } };
  export function randomUUID(): string;
}

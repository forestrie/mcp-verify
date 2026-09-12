/**
 * Hand-written declarations for `self-register.mjs`, so `test/node/*.test.ts`
 * can import it under `strict` without an implicit-any module error.
 * `scripts/` is excluded from `tsconfig.build.json` (this script ships as
 * plain JS, unbuilt) but is still typechecked via `test/**` importing it —
 * keep this file in sync with the exports below by hand.
 */

export declare class SelfRegisterError extends Error {}

export interface SelfRegisterProvenance {
  name: string;
  version: string;
  gitCommit: string;
  builtAt: string;
}

export interface SelfRegisterResult {
  outDir: string;
  entryId: string;
  provenance: SelfRegisterProvenance;
}

export interface CliRunResult {
  status: number;
  stdout: string;
  stderr: string;
}

export type EnvRecord = Record<string, string | undefined>;

export interface SelfRegisterOptions {
  env?: EnvRecord;
  dryRun?: boolean;
  outDir?: string;
  log?: (message: string) => void;
  now?: () => Date;
  resolveCli?: (ctx: {
    env: EnvRecord;
    log: (message: string) => void;
  }) => Promise<string>;
  runCli?: (bin: string, args: string[]) => CliRunResult;
  fetchGenesis?: (
    baseUrl: string,
    logId: string,
    ctx?: { env: EnvRecord; log: (message: string) => void },
  ) => Promise<Uint8Array>;
}

export declare function selfRegister(
  opts?: SelfRegisterOptions,
): Promise<SelfRegisterResult>;

export declare function parseArgs(argv: string[]): {
  dryRun: boolean;
  outDir?: string;
};

export declare function derivePublicKeyXyBase64(keyPem: string): string;

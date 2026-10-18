/**
 * Hand-written type declaration for check-encoding-single-copy.mjs, so
 * test/node/check-encoding-single-copy.test.ts can import the pure walk
 * under `tsc --noEmit`.
 */
export declare function findCopies(rootDir: string): Map<string, string[]>;

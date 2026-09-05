import { defineConfig } from "vitest/config";

/**
 * Two named projects so `pnpm test` stays hermetic and CI can run the
 * differential leg as its own job. A GitHub-release outage must be a
 * distinguishable red, not a mysterious unit-test failure.
 */
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "unit",
          environment: "node",
          include: ["test/core/**/*.test.ts", "test/node/**/*.test.ts"],
          // D2(b): every test in this project runs with a fetch that throws.
          setupFiles: ["./test/setup/forbidden-fetch.ts"],
        },
      },
      {
        test: {
          name: "differential",
          environment: "node",
          include: ["test/differential/**/*.test.ts"],
          // The differential harness spawns the reference CLI, which is
          // allowed to do whatever it likes; only OUR code is fetch-gated,
          // and it is gated in the unit project.
          testTimeout: 60_000,
          hookTimeout: 300_000, // first run downloads the pinned binary
        },
      },
    ],
  },
});

import { defineConfig } from "vitest/config";

/**
 * One named project, `unit`, which the `test` and `test:unit` scripts select.
 * Every test in it runs with a fetch that throws, so `pnpm test` stays
 * hermetic.
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
    ],
  },
});

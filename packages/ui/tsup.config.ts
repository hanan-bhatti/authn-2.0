import { defineConfig } from "tsup";

/**
 * Authn Platform — @authn/ui build
 * File: packages/ui/tsup.config.ts
 *
 * Two passes, because the two module formats have incompatible requirements.
 *
 * ESM is what a bundler and a React Server Components graph read, and there
 * `"use client"` has to survive as the first statement of the file that declares
 * it. Bundling defeats that: forty components collapsed into one module means
 * the directive is either absent — and importing a static Badge drags every
 * hook-calling component into the server graph and fails the build — or present
 * on all of them, which makes the whole library a client boundary. Compiling
 * each source file to its own output keeps the directives where they were
 * written, so only the sixteen components that need a client boundary get one.
 *
 * CJS is reached by `require`, which no RSC graph does, so a directive would
 * mean nothing there and one bundled file is the better artefact.
 */
export default defineConfig([
  {
    entry: ["src/**/*.ts", "src/**/*.tsx"],
    format: ["esm"],
    bundle: false,
    dts: false,
    clean: true,
    sourcemap: true,
    minify: false,
  },
  {
    entry: ["src/index.ts"],
    format: ["cjs"],
    bundle: true,
    dts: false,
    // The ESM pass has already cleaned; cleaning again would delete its output.
    clean: false,
    sourcemap: true,
    minify: false,
    splitting: false,
    external: ["react", "react-dom"],
  },
]);

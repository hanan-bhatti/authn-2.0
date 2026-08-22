import { defineConfig } from "tsup";

import pkg from "./package.json";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    pkce: "src/pkce.ts",
    "admin/index": "src/admin/index.ts",
  },
  format: ["cjs", "esm"],
  dts: false,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  minify: false,
  target: "es2020",
  outDir: "dist",
  // SDK_VERSION reads this rather than repeating the number in source, where the
  // two would drift on the next release and the SDK would then misreport itself
  // in bug reports and User-Agent strings.
  define: {
    __SDK_VERSION__: JSON.stringify(pkg.version),
  },
});

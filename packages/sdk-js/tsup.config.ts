import { defineConfig } from "tsup";

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
});

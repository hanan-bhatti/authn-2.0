import fs from "node:fs";
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: false,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  external: ["react", "react-dom", "@authn/js"],
  async onSuccess() {
    const files = ["dist/index.js", "dist/index.cjs"];
    for (const file of files) {
      if (fs.existsSync(file)) {
        const content = fs.readFileSync(file, "utf8");
        if (!content.startsWith('"use client";')) {
          fs.writeFileSync(file, `"use client";\n${content}`);
        }
      }
    }
  },
});

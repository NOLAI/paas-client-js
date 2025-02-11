import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import { defineConfig } from "rollup";
import dts from "rollup-plugin-dts";

export default defineConfig([
  // Node Browser Build
  {
    input: "src/index.ts",
    output: {
      file: "dist/paas-client.browser.js",
      format: "es",
      name: "PaaSClient",
    },
    plugins: [
      commonjs(), // Handle CommonJS modules
      resolve({
        browser: true, // Resolve browser-friendly modules
        extensions: [".js", ".ts"], // Default extensions
      }),
      typescript(), // Compile TypeScript
    ],
    external: ["@nolai/libpep-wasm"],
  },
  // ESM Browser Build
  {
    input: "src/index.ts",
    output: {
      file: "dist/paas-client.browser.plain.js",
      format: "iife",
      name: "PaaSClient",
      globals: {
        "@nolai/libpep-wasm": "libpep",
      },
    },
    plugins: [
      commonjs(), // Handle CommonJS modules
      resolve({
        browser: true, // Resolve browser-friendly modules
        extensions: [".js", ".ts"], // Default extensions
      }),
      typescript(), // Compile TypeScript
    ],
    external: ["@nolai/libpep-wasm"],
  },
  // Node.js Build
  {
    input: "src/index.ts",
    output: {
      file: "dist/paas-client.js",
      format: "es",
    },
    plugins: [resolve({ preferBuiltins: true }), commonjs(), typescript()],
    external: ["@nolai/libpep-wasm"],
  },
  // Type definitions bundle
  {
    input: "src/index.ts",
    output: [{
      file: "dist/paas-client.d.ts",
      format: "es"
    }],
    plugins: [dts()],
    external: ["@nolai/libpep-wasm"]
  }
]);

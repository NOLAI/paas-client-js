import eslint from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

export default {
  files: ["src/**/*.ts", "tests/**/*.ts"],
  languageOptions: {
    parser: tsparser,
  },
  plugins: {
    eslint,
    tseslint,
  },
  rules: {
    "no-console": "warn",
    camelcase: "error",
  },
};

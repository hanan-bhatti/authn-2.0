/** @type {import('eslint').Linter.FlatConfig[]} */
module.exports = [
  {
    ignores: ["node_modules/", "dist/", ".next/", "coverage/"],
  },
  {
    files: ["**/*.ts", "**/*.tsx"],
    rules: {
      "no-console": ["warn", { allow: ["warn", "error"] }],
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/explicit-module-boundary-types": "off",
      "@typescript-eslint/no-explicit-any": "error",
      "react/react-in-jsx-scope": "off",
    },
  },
];

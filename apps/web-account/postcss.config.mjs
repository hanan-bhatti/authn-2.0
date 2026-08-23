/**
 * Authn Platform — Account app PostCSS configuration
 * File: apps/web-account/postcss.config.mjs
 *
 * Tailwind v4 is a PostCSS plugin rather than a CLI step, and it is the only
 * plugin needed: autoprefixing and nesting are handled inside it via Lightning
 * CSS, so adding autoprefixer alongside it duplicates work.
 */

const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;

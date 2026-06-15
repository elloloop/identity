import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import expressiveCode from "astro-expressive-code";
import pagefind from "astro-pagefind";

// Single source of truth for the docs version: the repo-root VERSION file.
// Inlined at build time so it's available both during SSG prerender and in
// the client bundle without filesystem access at runtime.
const DOCS_VERSION = readFileSync(
  fileURLToPath(new URL("../VERSION", import.meta.url)),
  "utf8",
).trim();

export default defineConfig({
  site: "https://elloloop.github.io",
  base: "/identity",
  integrations: [
    expressiveCode({
      themes: ["github-dark-dimmed"],
      styleOverrides: {
        // Minimal, modern chrome — drop the macOS "traffic light" decoration.
        frames: {
          frameBoxShadowCssValue: "none",
          editorTabBarBackground: "hsl(var(--muted))",
          editorActiveTabIndicatorBottomColor: "hsl(var(--primary))",
          editorActiveTabBorderColor: "transparent",
          terminalTitlebarBackground: "hsl(var(--muted))",
          terminalTitlebarBorderBottomColor: "hsl(var(--border))",
          terminalBackground: "#22272e",
          tooltipSuccessBackground: "hsl(var(--primary))",
        },
        borderRadius: "0.5rem",
        codeFontFamily: "var(--font-mono)",
        codeFontSize: "13px",
        codeLineHeight: "1.65",
        uiFontFamily: "var(--font-sans)",
      },
      defaultProps: {
        // Hide the macOS-style window decoration buttons globally.
        frame: "code",
      },
      shiki: {
        // Match the prior Shiki configuration so language tags continue to work.
      },
    }),
    pagefind(),
  ],
  vite: {
    plugins: [tailwindcss()],
    define: {
      __DOCS_VERSION__: JSON.stringify(DOCS_VERSION),
    },
    build: {
      rollupOptions: {
        // @refraction-ui/astro's optional analytics sinks dynamically import
        // third-party SDKs (PostHog, Azure Application Insights) without
        // declaring them as dependencies. The docs site doesn't enable any
        // analytics sink, so these code paths never run — externalize them
        // rather than pulling unused analytics SDKs into the build.
        external: ["posthog-js", "@microsoft/applicationinsights-web"],
      },
    },
  },
  output: "static",
});

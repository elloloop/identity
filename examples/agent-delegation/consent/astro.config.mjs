import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({
  output: 'static', build: { inlineStylesheets: 'always' },
  vite: { plugins: [tailwindcss()], build: { rollupOptions: { external: ['posthog-js', '@microsoft/applicationinsights-web'] } } },
});

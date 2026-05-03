import { defineConfig } from "astro/config";
import tailwind from "@astrojs/tailwind";

export default defineConfig({
  site: "https://elloloop.github.io",
  base: "/identity",
  integrations: [tailwind({ applyBaseStyles: false })],
  output: "static",
});

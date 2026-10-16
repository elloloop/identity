import { refractionPreset } from '@refraction-ui/tailwind-config';
export default {
  presets: [refractionPreset],
  content: ['./src/**/*.{astro,js}', './node_modules/@refraction-ui/astro/dist/**/*.{astro,ts}'],
};

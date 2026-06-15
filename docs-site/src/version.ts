// Single source of truth for the displayed docs version.
//
// The value is the repo-root VERSION file, inlined at build time via the
// `__DOCS_VERSION__` define in astro.config.mjs. The same VERSION file feeds
// the OpenAPI spec's info.version (scripts/prepare-openapi.mjs), so the docs
// version, the VersionPill, and the API reference all track one value. Bump
// VERSION (repo root) to release a new docs version.

declare const __DOCS_VERSION__: string;

/** Bare version string from the repo VERSION file, e.g. "0.2.2". */
export const DOCS_VERSION = __DOCS_VERSION__;

/** Display form used in the version pill, e.g. "v0.2.2". */
export const DOCS_VERSION_LABEL = `v${DOCS_VERSION}`;

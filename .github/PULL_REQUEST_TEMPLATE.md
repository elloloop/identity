<!--
Thanks for contributing. Fill out the sections below before requesting review.
The CI pipeline (lint + vuln + test + smoke + integration + realentdb + realpostgres + fuzz + docker) must be green to merge.
-->

## Summary

<!-- One-paragraph description of what changes and why. Link the issue this closes. -->

Closes #

## What changed

<!-- Bullet list of the substantive changes. Skip for trivial PRs. -->

-

## Test plan

<!--
How did you verify this works? Be specific.
For bug fixes: include a regression test in the diff and reference it here.
For features: list the tests you added (unit / integration / realentdb / realpostgres).
-->

- [ ] Added or updated unit tests
- [ ] Added or updated integration tests (`-tags=integration`)
- [ ] Added or updated real-DB tests (`-tags=realentdb` / `-tags=realpostgres`) if behavior depends on storage
- [ ] Documented public-facing changes in `docs-site/`

## Risk

<!-- What could break? What's the blast radius? Multi-replica considerations? -->

## Backward compatibility

<!-- Does this change a wire format, env var, schema, or public API? If yes, describe migration. -->

## Engineering rules checklist

See [AGENTS.md](../AGENTS.md). The following must be true:

- [ ] No patch fixes / shims / compatibility layers — wrong shapes are fixed, not wrapped
- [ ] No dead code left behind from a refactor
- [ ] No half-finished implementations (impl + tests + wiring all land together)
- [ ] Bug fixes ship with regression tests
- [ ] Commit messages are imperative, no AI attribution, no inaccessible-context references

# ADR-0014 — Hosted action pages (emailed links land on identity's own pages)

## Status

Accepted (2026-09-10).

Extends the hosted auth UI shipped for the sign-in page (`/auth/`) and the
hosted OAuth flow's one-time-code handover (ADR-0011). Two follow-ups are
scoped here and deferred: per-project override URLs for emailed links, and
theming the hosted pages with a product's design tokens.

## Context

Identity mails five kinds of link — email verification, password reset,
email-change confirmation, magic link, invitation acceptance — and every one
of them has the shape `{base}/auth/<action>?token=…`. `{base}` is the
project's primary auth-domain when it has one, else `GATEWAY_APP_BASE_URL`.

Until this decision nothing served those paths. The hosted UI rendered its
sign-in page for the bare `/auth/` and 404'd everything else, so every mailed
link was dead unless the operator's own frontend implemented all five routes
itself — which the documentation asked it to. A project with a primary
auth-domain could not be rescued that way at all: its base is identity's own
host, so its links always landed on the 404. PR #498 reported the symptom for
verification links and proposed moving that one link to a different path,
which would have left four dead links and one that a frontend must implement
under a different contract.

This is the same problem every hosted identity provider solves the same way:
Firebase's action handler, Supabase's `/auth/v1/verify`, Auth0 and Cognito
all host the pages an emailed link lands on, branded to the product, with the
option for a product to point a link at its own page instead.

## Decision

### Identity serves the five pages, at the paths links already use

`/auth/verify-email`, `/auth/reset-password`, `/auth/confirm-email-change`,
`/auth/magic-link` and `/auth/accept-invitation` are rendered by the hosted UI
handler. Because the mailed URLs did not change, no deployment's links moved:
a base URL pointing at identity now reaches a working page, a project on its
own auth-domain works for the first time, and a frontend that already serves
the `/auth/*` routes is untouched.

### A GET only looks; a POST is the click

The pages are server-rendered forms with no script. A GET previews the token
without consuming it — the page shows whose address the link concerns and
whether the link is still live, already used, or expired — so a mail scanner
or a link preview cannot spend a single-use token. Only the form POST consumes
it, through the same service method the RPC uses, so every check the RPC
enforces (expiry, single use, access policy, login policy, password policy)
applies unchanged.

### Nothing on these pages mints a session, except through the handover code

Verifying an address, confirming a change, resetting a password and accepting
an invitation all end on a page that says what happened and offers the
sign-in page. Clicking a link proves control of an inbox at that moment, not
ownership of an account, so it must not log the clicker in. The RPCs that
issue a session today (`AcceptInvitation`) keep doing so; the hosted page
calls a variant (`RedeemInvitation`) that stops before the session.

The magic link is the one link that *is* a sign-in. Its hosted page cannot
hand tokens to an app safely — a fragment leaks to history and Referer,
cookies are awkward cross-origin and useless to native clients (ADR-0011) —
so it does what the hosted OAuth callback does: it establishes the user,
mints a single-use handover code bound to that user, and redirects to the
link's stored `return_to` with `?code=`. The app redeems the code with
`RedeemOAuthCode`, which keeps its name because the wire contract did not
change. The code record now carries the flow that minted it (`login_method`,
migration 0033 / SQLite 0018), and redeem enforces that flow's login policy
and writes that flow's audit event: a magic-link code completes as a
passwordless login, an OAuth code as an OAuth login, and an unknown method is
refused. `RedeemOAuthCode` is Unavailable only when neither OAuth providers
nor the hosted return allowlist is configured — the two things that can mint
a code. The stored `return_to` is re-checked against the current allowlist
when the link is consumed.

### Security posture of the pages

- Cross-site POSTs are refused with `net/http`'s `CrossOriginProtection`,
  which reads the browser's Fetch metadata (`Sec-Fetch-Site`, `Origin`) and
  needs no cookie — so a user whose browser blocks cookies is never locked
  out, and a page on another origin cannot submit the magic-link form to
  log a victim into an attacker's account.
- Every `/auth/*` response carries `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer` (the URL holds the token), a per-request
  nonce Content-Security-Policy with `default-src 'none'` and
  `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options:
  nosniff` and `X-Robots-Tag: noindex`. The action pages admit no script at
  all; the sign-in page admits its own nonced script and, only when a
  Turnstile site key is configured, the Turnstile origin for the loader and
  the widget frame.
- `form-action 'self'` is set on every page except the magic-link page:
  Chrome applies `form-action` to the redirect that follows a form
  submission, which would block the handover.
- Redirect targets are never taken from the request: the magic-link page
  redirects only to the link's stored, allowlisted `return_to`; every other
  page links to the sign-in page on the same origin.
- The hosted POSTs share the per-IP budgets of the RPC surfaces they stand in
  for (verify, reset, login, signup).

### Tenant invitations get their own page

A tenant-membership invitation (`CreateTenantInvitation`) is accepted by a
signed-in caller whose address matches (`AcceptTenantInvitation`), so no
server-rendered page can complete it. It also lives in a different store
from the admin user invitation while sharing its URL, which is how a live
tenant invitation would have been reported "invalid" by the accept-invitation
page. It now mails `/auth/join-team`, a page that only looks: it names the
team and the invited address and sends the invitee to sign in.

### Deferred, in scope of this program

- **Override URLs.** A product that wants its own page for a link kind will
  say so per project (`config_json.email_links.<kind>`) with env equivalents
  for the default project; the hosted page stays the default. Per-request
  URLs are rejected: on an unauthenticated RPC such as `RequestPasswordReset`
  a per-request URL is a token-exfiltration channel unless allowlisted, and
  the magic link already carries the one allowlisted per-request target.
- **Theming.** The pages will read a project's Refraction design tokens,
  logo and favicon so they look like the product; today they carry the
  product name and support address from the existing `branding` block.
- **Hub-served projects without an auth-domain.** Their links reach the
  hub, which resolves the default project; the presented project key is not
  carried into request context, so a link cannot embed it yet. Such a
  project sets a primary auth-domain until it can.
- **Requesting a new link from the hosted sign-in page.** The used and
  expired states send the user back to the app; the hosted sign-in page has
  no forgot-password or magic-link request yet.
- **Localisation.** The hosted copy is English only; a product needing other
  languages serves its own routes.
- **Metrics.** The hosted pages are log-observable only; the RPC metrics
  middleware does not cover them.

## Consequences

- Operators get working links with zero frontend work; a frontend that built
  the pages keeps working; auth-domain projects work for the first time.
- `RedeemOAuthCode` is now the redeem step for every hosted handover. Its
  audit detail for the OAuth flow reads `{"method":"oauth","via":
  "hosted_handover"}` (was `{"method":"hosted_redeem"}`); a magic-link
  redeem records `login_success` with `{"method":"magic_link","via":
  "hosted_handover"}`, and the consume itself records `magic_link_consumed`
  with `new_user`, so proving control of an inbox is in the audit log even
  when the code is never redeemed. The response carries `totp_required` and
  `login_challenge_id` for a second-factor requirement.
- The sign-in page answers GET and HEAD only, and can no longer be framed.
- The hosted UI package owns a `Service` interface of twelve methods; the
  service layer gained read-only previews (`Peek*`), `RedeemInvitation`,
  `RedeemMagicLinkForHandover`, `HostedUIBranding`, and one repository
  method (`FindMagicLinkTokenByHash`) implemented by all drivers and covered
  by the conformance suite.

## Alternatives rejected

- **Change the mailed path for one link (PR #498).** Leaves four dead links
  and moves the frontend contract for the fifth.
- **Auto-consume on GET.** Simpler page, but link scanners and previewers
  would spend tokens before the user sees the page.
- **Cookie-based CSRF for the action forms.** The hosted OAuth flow uses a
  `__Host-` cookie; here Fetch-metadata checking gives the same protection
  without a failure mode for cookie-blocking browsers and without `Secure`
  cookie problems over plain-HTTP development.
- **Hand tokens to the app in the URL fragment.** Rejected in ADR-0011 for
  the same reasons it is rejected here.
- **A new `RedeemHandoverCode` RPC.** A rename with no wire benefit; the
  existing RPC's semantics widened and its documentation says so.

(() => {
  'use strict';
  const config = JSON.parse(document.getElementById('agent-config').textContent);
  const query = new URLSearchParams(location.search);
  const id = query.getAll('request_id');
  const project = query.getAll('project_key');
  const byId = (value) => document.getElementById(value);
  let token = '', challenge = '', view = null, busy = false, selected = '', captchaToken = '', captchaWidget = null;
  const seen = new Set();
  const loginIntentKey = 'identity.agent-consent.login.v1';
  const loginIntentLifetime = 15 * 60 * 1000;
  const providerButtons = [];
  const providerKeys = new Set();
  const providerLabels = { google: 'Google', microsoft: 'Microsoft', github: 'GitHub', apple: 'Apple', oidc: 'OIDC' };
  function consentReturnURL() {
    const target = new URL(location.pathname, location.origin);
    target.searchParams.set('request_id', requestID);
    if (projectKey) target.searchParams.set('project_key', projectKey);
    return target;
  }
  async function loginContext() {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(consentReturnURL().href));
    return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function providerOrigin(provider) {
    const origin = provider.startOrigin || location.origin;
    try {
      const parsed = new URL(origin);
      const local = ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
      if (parsed.origin !== origin || !(parsed.protocol === 'https:' || (local && parsed.protocol === 'http:'))) return null;
      return origin;
    } catch { return null; }
  }
  function renderProviders() {
    const providers = Array.isArray(config.oauthProviders) ? config.oauthProviders : [];
    if (config.hostedOAuthEnabled) {
      for (const provider of providers) {
        if (!/^[a-z][a-z0-9_-]{0,63}$/.test(provider.key) || (provider.needsProjectKey && !projectKey)) continue;
        const origin = providerOrigin(provider);
        if (!origin || providerKeys.has(provider.key)) continue;
        const button = byId('oauth-button-template').content.firstElementChild.cloneNode(true);
        button.querySelector('span').textContent = 'Continue with ' + (providerLabels[provider.key] || provider.key);
        button.addEventListener('click', () => action(async () => {
          const state = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
          const intent = { state, context: await loginContext(), provider: provider.key, expires: Date.now() + loginIntentLifetime };
          try { sessionStorage.setItem(loginIntentKey, JSON.stringify(intent)); }
          catch { throw new Error('This browser cannot retain the sign-in request. Allow session storage or use another browser.'); }
          const target = consentReturnURL(); target.searchParams.set('login_state', state);
          const start = new URL('/oauth/start/' + encodeURIComponent(provider.key), origin);
          start.searchParams.set('return_to', target.href);
          if (projectKey) start.searchParams.set('project_key', projectKey);
          location.assign(start.href);
        }));
        providerKeys.add(provider.key); providerButtons.push(button); byId('oauth-buttons').append(button);
      }
    }
    byId('oauth-buttons').hidden = providerButtons.length === 0;
    byId('oauth-divider').hidden = !config.passwordLoginEnabled || providerButtons.length === 0;
    if (!config.passwordLoginEnabled && providerButtons.length === 0) {
      byId('no-login').hidden = false;
      if (providers.some(provider => provider.needsProjectKey) && !projectKey) byId('no-login').textContent = 'Your organization’s sign-in needs the original project-scoped request link. Start again from the requesting app.';
    }
    if (providers.length && !config.hostedOAuthEnabled) {
      byId('no-login').hidden = false;
      byId('no-login').textContent = 'Hosted sign-in cannot return to this consent page under the server’s allowed return policy. Contact your administrator. No access has been granted.';
    }
  }
  async function resumeHostedLogin() {
    const codes = query.getAll('code'), errors = query.getAll('error'), states = query.getAll('login_state');
    if (!codes.length && !errors.length && !states.length) return;
    let intent;
    try {
      const saved = sessionStorage.getItem(loginIntentKey);
      sessionStorage.removeItem(loginIntentKey);
      if (saved && saved.length <= 1024) intent = JSON.parse(saved);
    } catch { throw new Error('This browser could not verify the sign-in return. Start sign-in again.'); }
    if (states.length !== 1 || !/^[a-f0-9]{64}$/.test(states[0]) || !intent || intent.state !== states[0] ||
        intent.context !== await loginContext() || !Number.isFinite(intent.expires) || intent.expires <= Date.now() ||
        intent.expires > Date.now() + loginIntentLifetime || !providerButtons.length ||
        !providerKeys.has(intent.provider) ||
        codes.length + errors.length !== 1 || (codes.length && (!codes[0] || codes[0].length > 1024))) {
      throw new Error('This sign-in return does not match this browser and authorization request. Start sign-in again.');
    }
    if (errors.length) throw new Error('Sign-in was canceled or refused. No access has been granted. You can try signing in again.');
    await signedIn(await rpc('RedeemOAuthCode', { code: codes[0] }));
  }

  const requestID = id.length === 1 && id[0].length <= 128 ? id[0] : '';
  const projectKey = project.length === 1 && project[0].length <= 256 ? project[0] : '';
  // The one-time code must leave the address bar before any await or external script.
  if (['code', 'error', 'login_state'].some(key => query.has(key))) {
    history.replaceState(null, '', consentReturnURL().pathname + consentReturnURL().search);
  }
  const errorText = {
    unauthenticated: 'Please sign in again to review this request.',
    permission_denied: 'You can’t authorize this request. No access has been granted.',
    failed_precondition: 'This request or your sign-in is no longer current. Start again from the requesting app.',
    not_found: 'This request is unavailable. Start again from the requesting app.',
    resource_exhausted: 'Too many attempts. Please wait and try again.',
  };
  function showError(message) { byId('error').textContent = message; byId('error').hidden = false; }
  function disabled(id, value) {
    const button = byId(id); button.disabled = value;
    button.setAttribute('aria-disabled', String(value));
    button.toggleAttribute('data-disabled', value);
  }
  function updateButtons() {
    const expired = !view || Date.now() >= Number(view.requestExpiresAtMs);
    disabled('approve', busy || expired || !selected);
    disabled('deny', busy || expired);
    disabled('sign-in', busy);
    disabled('more-agents', busy || expired);
    for (const button of providerButtons) button.disabled = busy;
  }
  async function rpc(method, body, extra = {}) {
    const headers = { 'Content-Type': 'application/json', 'Connect-Protocol-Version': '1', ...extra };
    if (projectKey) headers['X-Project-Key'] = projectKey;
    if (token) headers.Authorization = 'Bearer ' + token;
    const result = await fetch('/identity.v1.IdentityService/' + method, {
      method: 'POST', headers, body: JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error',
    });
    const data = await result.json();
    if (!result.ok) {
      const reauthenticate = data.code === 'unauthenticated' || (data.code === 'failed_precondition' && String(data.message || '').startsWith('reauthentication_required:'));
      const error = new Error(reauthenticate ? 'Please sign in again to review this request.' : errorText[data.code] || 'The request could not be completed. Check the requesting app before retrying.');
      error.reauthenticate = reauthenticate; throw error;
    }
    return data;
  }
  async function action(work) {
    if (busy) return;
    busy = true; byId('error').hidden = true; updateButtons();
    try { await work(); } catch (error) {
      if (error.reauthenticate && token) {
        token = ''; challenge = ''; view = null; selected = ''; resetCaptcha();
        byId('review-panel').hidden = true; byId('login-panel').hidden = false; byId('totp-form').hidden = true;
        byId('login-form').hidden = !config.passwordLoginEnabled; byId('password').value = '';
        byId('status').textContent = 'Your sign-in needs to be confirmed again. No access is approved automatically.';
        (providerButtons[0] || byId('identifier')).focus();
      }
      showError(error.message || 'Connection failed. Check the requesting app before retrying.');
    }
    finally { busy = false; updateButtons(); }
  }
  function appendAgents(agents) {
    for (const agent of agents || []) {
      if (!agent.id || seen.has(agent.id)) continue;
      seen.add(agent.id);
      const label = document.createElement('label'); label.className = 'agent-choice';
      const input = document.createElement('input'); input.type = 'radio'; input.name = 'agent'; input.value = agent.id;
      input.addEventListener('change', () => { selected = input.value; updateButtons(); });
      const name = document.createElement('span'); name.textContent = agent.name || 'Unnamed agent';
      label.append(input, name); byId('agents').append(label);
    }
    byId('empty').hidden = seen.size > 0;
  }
  function expiry() {
    if (!view) return;
    const remaining = Number(view.requestExpiresAtMs) - Date.now();
    byId('request-expiry').textContent = remaining > 0
      ? 'Review within ' + Math.ceil(remaining / 60000) + (Math.ceil(remaining / 60000) === 1 ? ' minute.' : ' minutes.') + ' Nothing is approved until you choose Allow.'
      : 'This request has expired. Start again from the requesting app.';
    updateButtons();
  }
  async function loadReview() {
    view = await rpc('GetAgentAuthorization', { requestId: requestID, agentOffset: 0 });
    if (view.requestId !== requestID || !view.revision || !view.resource || !Array.isArray(view.scopes) || !view.scopes.length || !Number.isFinite(Number(view.requestExpiresAtMs)) || !Number.isFinite(Number(view.grantExpiresAtMs)) || Number(view.requestExpiresAtMs) <= Date.now() || Number(view.grantExpiresAtMs) <= Date.now()) {
      view = null; throw new Error('This request could not be verified. Start again from the requesting app.');
    }
    seen.clear(); selected = ''; byId('agents').replaceChildren();
    byId('review-title').textContent = 'Authorize access to ' + view.product;
    byId('client-name').textContent = view.clientName || view.clientId;
    byId('resource').textContent = view.resource;
    byId('grant-expiry').textContent = new Date(Number(view.grantExpiresAtMs)).toLocaleString();
    byId('scopes').replaceChildren();
    for (const scope of view.scopes) { const item = document.createElement('li'); item.textContent = scope; byId('scopes').append(item); }
    appendAgents(view.agents); byId('more-agents').hidden = Number(view.nextAgentOffset ?? -1) < 0;
    byId('login-panel').hidden = true; byId('review-panel').hidden = false;
    byId('status').textContent = 'Signed in. Review the access before continuing.';
    expiry(); byId('review-title').tabIndex = -1; byId('review-title').focus();
  }
  async function signedIn(data) {
    if (!data.accessToken) throw new Error('Sign-in did not finish. No access has been granted.');
    token = data.accessToken; challenge = ''; byId('password').value = ''; byId('totp-code').value = '';
    await loadReview();
  }
  function resetCaptcha() {
    captchaToken = '';
    if (captchaWidget !== null && window.turnstile) window.turnstile.reset(captchaWidget);
  }
  byId('login-form').addEventListener('submit', (event) => {
    event.preventDefault();
    action(async () => {
      const extra = {};
      if (config.captchaEnforceLogin) {
        if (!captchaToken) throw new Error('Complete the verification before signing in. If it did not load, reload this page.');
        const proof = await rpc('IssueAssuranceToken', { platform: 'web', webToken: captchaToken });
        extra['X-Assurance-Token'] = proof.assuranceToken;
      }
      try {
        const data = await rpc('PasswordLogin', { email: byId('identifier').value, password: byId('password').value }, extra);
        byId('password').value = '';
        if (data.totpRequired && data.loginChallengeId) {
          challenge = data.loginChallengeId; byId('login-form').hidden = true; byId('totp-form').hidden = false; byId('totp-code').focus();
          byId('status').textContent = 'Enter your authenticator or recovery code to finish signing in.';
        } else await signedIn(data);
      } finally { resetCaptcha(); }
    });
  });
  byId('totp-form').addEventListener('submit', (event) => {
    event.preventDefault(); action(async () => { await signedIn(await rpc('VerifyTotp', { loginChallengeId: challenge, code: byId('totp-code').value })); });
  });
  byId('more-agents').addEventListener('click', () => action(async () => {
    const offset = Number(view.nextAgentOffset ?? -1);
    if (offset < 0) return;
    const more = await rpc('GetAgentAuthorization', { requestId: requestID, agentOffset: offset });
    if (more.requestId !== view.requestId || more.revision !== view.revision || more.resource !== view.resource || JSON.stringify(more.scopes) !== JSON.stringify(view.scopes)) throw new Error('This request changed. Start again from the requesting app.');
    view.nextAgentOffset = more.nextAgentOffset; appendAgents(more.agents); byId('more-agents').hidden = Number(more.nextAgentOffset ?? -1) < 0;
  }));
  function decide(allow) {
    action(async () => {
      if (!view || Date.now() >= Number(view.requestExpiresAtMs) || (allow && !selected)) return;
      const result = await rpc('DecideAgentAuthorization', { requestId: requestID, expectedRevision: view.revision,
        decision: allow ? 'AGENT_AUTHORIZATION_DECISION_APPROVE' : 'AGENT_AUTHORIZATION_DECISION_DENY', agentUserId: allow ? selected : '' });
      const redirect = new URL(result.redirectUri);
      const loopback = ['127.0.0.1', '[::1]'].includes(redirect.hostname);
      if (redirect.username || redirect.password || !(redirect.protocol === 'https:' || (redirect.protocol === 'http:' && loopback))) throw new Error('The app callback could not be verified. Close this page and check the requesting app.');
      token = ''; byId('status').textContent = allow ? 'Approved. Returning to the requesting app…' : 'Not allowed. Returning to the requesting app…';
      location.assign(redirect.href);
    });
  }
  byId('approve').addEventListener('click', () => decide(true));
  byId('deny').addEventListener('click', () => decide(false));
  window.addEventListener('pagehide', () => { token = ''; challenge = ''; captchaToken = ''; });
  if (!requestID || id[0] === '' || project.length > 1 || (project.length === 1 && !projectKey)) {
    try { sessionStorage.removeItem(loginIntentKey); } catch {}
    byId('login-panel').hidden = true; showError('This authorization link is incomplete. Start again from the requesting app.');
    return;
  }
  if (!config.passwordLoginEnabled) byId('login-form').hidden = true;
  renderProviders();
  action(resumeHostedLogin);
  if (config.usernameLoginEnabled) { byId('identifier').type = 'text'; byId('identifier-label').textContent = 'Email or username'; }
  if (config.captchaEnforceLogin && config.passwordLoginEnabled) {
    byId('captcha').hidden = false;
    if (config.captchaProvider !== 'turnstile' || !config.captchaSiteKey) { byId('sign-in').disabled = true; showError('Sign-in verification is unavailable. Contact your administrator.'); return; }
    const script = document.createElement('script'); script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.onload = () => { captchaWidget = window.turnstile.render(byId('captcha'), { sitekey: config.captchaSiteKey, callback: (value) => { captchaToken = value; }, 'expired-callback': () => { captchaToken = ''; }, 'error-callback': () => { captchaToken = ''; } }); };
    script.onerror = () => showError('Sign-in verification could not load. Check your connection and reload this page.'); document.head.append(script);
  }
  setInterval(expiry, 1000);
})();

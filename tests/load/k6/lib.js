import http from "k6/http";
import { check } from "k6";

export const baseURL = (__ENV.BASE_URL || "http://host.docker.internal:18080").replace(/\/+$/, "");

export function envInt(name, fallback) {
  const raw = __ENV[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) {
    throw new Error(`${name} must be an integer, got ${raw}`);
  }
  return value;
}

export function envFloat(name, fallback) {
  const raw = __ENV[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const value = Number.parseFloat(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`${name} must be a number, got ${raw}`);
  }
  return value;
}

export function envBool(name, fallback) {
  const raw = __ENV[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  return raw === "1" || raw === "true" || raw === "TRUE" || raw === "yes" || raw === "YES";
}

export function durationToSeconds(value) {
  const match = /^(\d+)(s|m|h)$/.exec(value);
  if (!match) {
    throw new Error(`unsupported duration ${value}; use Ns, Nm, or Nh`);
  }
  const amount = Number.parseInt(match[1], 10);
  switch (match[2]) {
    case "s":
      return amount;
    case "m":
      return amount * 60;
    case "h":
      return amount * 60 * 60;
    default:
      throw new Error(`unsupported duration unit in ${value}`);
  }
}

export function minimumCount(targetQPS, duration, factor = 0.98) {
  return Math.max(1, Math.floor(targetQPS * durationToSeconds(duration) * factor));
}

export function clip(value, max) {
  if (!value || value.length <= max) {
    return value;
  }
  return `${value.slice(0, max)}...`;
}

export function expectJSON(res, label) {
  return check(res, {
    [`${label} status is 200`]: (r) => r.status === 200,
    [`${label} content-type is json`]: (r) =>
      String(r.headers["Content-Type"] || "").includes("application/json"),
  });
}

export function expectSessionEnvelope(res, label) {
  return check(res, {
    [`${label} succeeded`]: (r) => r.status === 200,
    [`${label} returned access token`]: (r) => Boolean(r.json("accessToken")),
    [`${label} returned refresh token`]: (r) => Boolean(r.json("refreshToken")),
    [`${label} returned user id`]: (r) => Boolean(r.json("user.id")),
  });
}

export function expectStatus(res, label, status) {
  return check(res, {
    [`${label} status is ${status}`]: (r) => r.status === status,
  });
}

export function rpc(method, payload, extra = {}) {
  const headers = Object.assign(
    {
      "Content-Type": "application/json",
    },
    extra.headers || {},
  );
  const tags = Object.assign({ rpc: method }, extra.tags || {});
  const responseCallback = extra.expectedStatuses
    ? http.expectedStatuses.apply(null, extra.expectedStatuses)
    : undefined;
  return http.post(
    `${baseURL}/identity.IdentityService/${method}`,
    JSON.stringify(payload),
    {
      headers,
      tags,
      responseCallback,
    },
  );
}

export function buildUser(runID, suffix) {
  return {
    email: `${runID}-${suffix}@example.com`,
    password: `Load test pass ${runID} ${suffix}!`,
    name: `Load User ${suffix}`,
  };
}

export function signupUser(user) {
  return rpc("PasswordSignup", {
    email: user.email,
    password: user.password,
    name: user.name,
    recoveryEmail: user.email,
  });
}

export function loginUser(user) {
  return rpc("PasswordLogin", {
    email: user.email,
    password: user.password,
  });
}

export function refreshSession(refreshToken) {
  return rpc("RefreshToken", { refreshToken });
}

export function logoutSession(refreshToken) {
  return rpc("Logout", { refreshToken });
}

export function getCurrentUser(accessToken) {
  return rpc(
    "GetCurrentUser",
    {},
    {
      headers: { Authorization: `Bearer ${accessToken}` },
      expectedStatuses: [200, 401, 404],
    },
  );
}

export function seedUsers(count, prefix) {
  const runID = `${prefix}-${Date.now()}`;
  const users = [];

  for (let i = 0; i < count; i += 1) {
    const user = buildUser(runID, i);
    const signup = signupUser(user);
    if (!expectJSON(signup, "signup")) {
      throw new Error(`signup failed for ${user.email}: ${signup.status} ${clip(signup.body, 400)}`);
    }
    const body = signup.json();
    if (!body.accessToken || !body.refreshToken || !body.user || !body.user.id) {
      throw new Error(`signup response missing session fields for ${user.email}: ${clip(signup.body, 400)}`);
    }
    users.push(Object.assign({}, user, {
      userId: body.user.id,
      accessToken: body.accessToken,
      refreshToken: body.refreshToken,
    }));
  }

  return { runID, users };
}

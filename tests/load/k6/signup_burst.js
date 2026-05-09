import exec from "k6/execution";
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter } from "k6/metrics";

import {
  baseURL,
  buildUser,
  clip,
  envInt,
  expectStatus,
  getCurrentUser,
  loginUser,
  logoutSession,
  minimumCount,
} from "./lib.js";

const targetQPS = envInt("TARGET_QPS", 48);
const duration = __ENV.DURATION || "5m";
const batchSize = envInt("BATCH_SIZE", 6);
const preAllocatedVUs = envInt("PREALLOCATED_VUS", 24);
const maxVUs = envInt("MAX_VUS", 96);

if (targetQPS % batchSize !== 0) {
  throw new Error(`TARGET_QPS (${targetQPS}) must be divisible by BATCH_SIZE (${batchSize})`);
}

const duplicateUserViolations = new Counter("duplicate_user_violations");
const signupProbeFailures = new Counter("signup_probe_failures");

export const options = {
  discardResponseBodies: false,
  scenarios: {
    signup_burst: {
      executor: "constant-arrival-rate",
      rate: targetQPS / batchSize,
      timeUnit: "1s",
      duration,
      preAllocatedVUs,
      maxVUs,
    },
  },
  thresholds: {
    checks: ["rate>0.99"],
    duplicate_user_violations: ["count==0"],
    signup_probe_failures: ["count==0"],
    "http_req_failed{rpc:PasswordSignup}": ["rate<0.01"],
    "http_req_duration{rpc:PasswordSignup}": ["p(95)<450", "p(99)<750"],
    "http_reqs{rpc:PasswordSignup,scenario:signup_burst}": [`count>=${minimumCount(targetQPS, duration)}`],
    "http_req_failed{rpc:PasswordLogin}": ["rate<0.01"],
    "http_req_failed{rpc:Logout}": ["rate<0.01"],
  },
};

function signupBatch(user) {
  const payload = JSON.stringify({
    email: user.email,
    password: user.password,
    name: user.name,
    recoveryEmail: user.email,
  });
  const params = {
    headers: { "Content-Type": "application/json" },
    tags: { rpc: "PasswordSignup" },
  };

  return http.batch(
    Array.from({ length: batchSize }, () => ({
      method: "POST",
      url: `${baseURL}/identity.IdentityService/PasswordSignup`,
      body: payload,
      params,
    })),
  );
}

function probeAuthenticatingUserID(accessToken) {
  const deadline = Date.now() + 2000;
  for (;;) {
    const who = getCurrentUser(accessToken);
    if (who.status === 200) {
      return { userID: who.json("user.id") };
    }
    if (who.status !== 401 && who.status !== 404) {
      return { error: `GetCurrentUser probe failed: ${who.status} ${clip(who.body, 400)}` };
    }
    if (Date.now() >= deadline) {
      return { userID: "" };
    }
    sleep(0.05);
  }
}

export default function () {
  const collisionIndex = exec.scenario.iterationInTest;
  const user = buildUser(`signup-burst-${Date.now()}`, `${exec.vu.idInTest}-${collisionIndex}`);
  const responses = signupBatch(user);
  const authenticatedUserIDs = new Set();

  for (const res of responses) {
    check(res, {
      "signup batch status is 200": (r) => r.status === 200,
      "signup batch content-type is json": (r) =>
        String(r.headers["Content-Type"] || "").includes("application/json"),
      "signup batch returned access token": (r) => Boolean(r.json("accessToken")),
      "signup batch returned refresh token": (r) => Boolean(r.json("refreshToken")),
    });
    if (res.status !== 200) {
      console.error(`PasswordSignup failed for ${user.email}: ${res.status} ${clip(res.body, 400)}`);
      continue;
    }

    const probe = probeAuthenticatingUserID(res.json("accessToken"));
    if (probe.userID) {
      authenticatedUserIDs.add(probe.userID);
    } else if (probe.error) {
      signupProbeFailures.add(1);
      console.error(`${probe.error} for ${user.email}`);
    }
  }

  if (authenticatedUserIDs.size === 0) {
    signupProbeFailures.add(1);
    console.error(`no authenticating signup token observed for ${user.email}`);
  }

  if (authenticatedUserIDs.size > 1) {
    duplicateUserViolations.add(1);
    console.error(`duplicate user creation detected for ${user.email}: ${Array.from(authenticatedUserIDs).join(", ")}`);
  }

  const login = loginUser(user);
  expectStatus(login, "post-burst login", 200);
  if (login.status !== 200) {
    console.error(`PasswordLogin failed after signup burst for ${user.email}: ${login.status} ${clip(login.body, 400)}`);
    return;
  }

  const logout = logoutSession(login.json("refreshToken"));
  expectStatus(logout, "post-burst logout", 200);
  if (logout.status !== 200) {
    console.error(`Logout failed after signup burst for ${user.email}: ${logout.status} ${clip(logout.body, 400)}`);
  }
}

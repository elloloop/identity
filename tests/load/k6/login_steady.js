import exec from "k6/execution";
import { sleep } from "k6";

import {
  clip,
  envBool,
  envFloat,
  envInt,
  expectSessionEnvelope,
  expectStatus,
  loginUser,
  logoutSession,
  minimumCount,
  seedUsers,
} from "./lib.js";

const userCount = envInt("USERS", 512);
const targetQPS = envInt("TARGET_QPS", 60);
const duration = __ENV.DURATION || "30m";
const preAllocatedVUs = envInt("PREALLOCATED_VUS", 48);
const maxVUs = envInt("MAX_VUS", 160);
const sleepSeconds = envFloat("SLEEP_SECONDS", 0.05);
const cleanupLogout = envBool("CLEANUP_LOGOUT", true);

export const options = {
  discardResponseBodies: false,
  scenarios: {
    login_steady: {
      executor: "constant-arrival-rate",
      rate: targetQPS,
      timeUnit: "1s",
      duration,
      preAllocatedVUs,
      maxVUs,
    },
  },
  thresholds: {
    checks: ["rate>0.995"],
    "http_req_failed{rpc:PasswordLogin}": ["rate<0.005"],
    "http_req_duration{rpc:PasswordLogin}": ["p(95)<300", "p(99)<450"],
    "http_reqs{rpc:PasswordLogin,scenario:login_steady}": [`count>=${minimumCount(targetQPS, duration)}`],
    "http_req_failed{rpc:Logout}": ["rate<0.005"],
    "http_req_duration{rpc:Logout}": ["p(99)<300"],
  },
};

export function setup() {
  return seedUsers(userCount, "login-steady");
}

export default function (data) {
  const user = data.users[exec.scenario.iterationInTest % data.users.length];
  const login = loginUser(user);
  expectSessionEnvelope(login, "login");
  if (login.status !== 200) {
    console.error(`PasswordLogin failed for ${user.email}: ${login.status} ${clip(login.body, 400)}`);
    return;
  }

  if (cleanupLogout) {
    const logout = logoutSession(login.json("refreshToken"));
    expectStatus(logout, "logout", 200);
    if (logout.status !== 200) {
      console.error(`Logout failed for ${user.email}: ${logout.status} ${clip(logout.body, 400)}`);
      return;
    }
  }

  sleep(sleepSeconds);
}

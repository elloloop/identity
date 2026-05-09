import exec from "k6/execution";
import { sleep } from "k6";

import {
  clip,
  envFloat,
  envInt,
  expectSessionEnvelope,
  minimumCount,
  refreshSession,
  seedUsers,
} from "./lib.js";

const userCount = envInt("USERS", 256);
const targetQPS = envInt("TARGET_QPS", 180);
const duration = __ENV.DURATION || "30m";
const preAllocatedVUs = envInt("PREALLOCATED_VUS", 96);
const maxVUs = envInt("MAX_VUS", 288);
const sleepSeconds = envFloat("SLEEP_SECONDS", 0.02);

const vuState = {};

export const options = {
  discardResponseBodies: false,
  scenarios: {
    refresh_steady: {
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
    "http_req_failed{rpc:RefreshToken}": ["rate<0.005"],
    "http_req_duration{rpc:RefreshToken}": ["p(95)<250", "p(99)<350"],
    "http_reqs{rpc:RefreshToken,scenario:refresh_steady}": [`count>=${minimumCount(targetQPS, duration)}`],
  },
};

export function setup() {
  if (userCount < preAllocatedVUs) {
    throw new Error(`USERS (${userCount}) must be at least PREALLOCATED_VUS (${preAllocatedVUs}) for refresh_steady`);
  }
  return seedUsers(userCount, "refresh-steady");
}

function sessionForVU(data) {
  const vuID = exec.vu.idInTest;
  if (!vuState[vuID]) {
    const user = data.users[(vuID - 1) % data.users.length];
    vuState[vuID] = {
      email: user.email,
      refreshToken: user.refreshToken,
    };
  }
  return vuState[vuID];
}

export default function (data) {
  const session = sessionForVU(data);
  const refresh = refreshSession(session.refreshToken);
  expectSessionEnvelope(refresh, "refresh");
  if (refresh.status !== 200) {
    console.error(`RefreshToken failed for ${session.email}: ${refresh.status} ${clip(refresh.body, 400)}`);
    return;
  }

  session.refreshToken = refresh.json("refreshToken");
  sleep(sleepSeconds);
}

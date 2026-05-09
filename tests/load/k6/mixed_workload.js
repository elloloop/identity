import exec from "k6/execution";
import { sleep } from "k6";

import {
  buildUser,
  clip,
  envFloat,
  envInt,
  expectSessionEnvelope,
  expectStatus,
  loginUser,
  logoutSession,
  minimumCount,
  refreshSession,
  seedUsers,
  signupUser,
} from "./lib.js";

const userCount = envInt("USERS", 400);
const targetQPS = envInt("TARGET_QPS", 100);
const duration = __ENV.DURATION || "60m";
const preAllocatedVUs = envInt("PREALLOCATED_VUS", 80);
const maxVUs = envInt("MAX_VUS", 240);
const sleepSeconds = envFloat("SLEEP_SECONDS", 0.05);
const signupWeight = envInt("SIGNUP_WEIGHT", 5);
const loginWeight = envInt("LOGIN_WEIGHT", 20);
const refreshWeight = envInt("REFRESH_WEIGHT", 60);
const logoutWeight = envInt("LOGOUT_WEIGHT", 15);
const totalWeight = signupWeight + loginWeight + refreshWeight + logoutWeight;

const vuState = {};

export const options = {
  discardResponseBodies: false,
  scenarios: {
    mixed_workload: {
      executor: "constant-arrival-rate",
      rate: targetQPS,
      timeUnit: "1s",
      duration,
      preAllocatedVUs,
      maxVUs,
    },
  },
  thresholds: {
    checks: ["rate>0.99"],
    "http_req_failed": ["rate<0.01"],
    "http_req_duration{rpc:PasswordSignup}": ["p(99)<800"],
    "http_req_duration{rpc:PasswordLogin}": ["p(99)<400"],
    "http_req_duration{rpc:RefreshToken}": ["p(99)<250"],
    "http_req_duration{rpc:Logout}": ["p(99)<250"],
    "http_reqs{scenario:mixed_workload}": [`count>=${minimumCount(targetQPS, duration)}`],
  },
};

export function setup() {
  if (userCount < preAllocatedVUs) {
    throw new Error(`USERS (${userCount}) must be at least PREALLOCATED_VUS (${preAllocatedVUs}) for mixed_workload`);
  }
  return seedUsers(userCount, "mixed-workload");
}

function stateForVU(data) {
  const vuID = exec.vu.idInTest;
  if (!vuState[vuID]) {
    const user = data.users[(vuID - 1) % data.users.length];
    vuState[vuID] = {
      user,
      refreshToken: user.refreshToken,
    };
  }
  return vuState[vuID];
}

function assignSession(state, user, refreshToken) {
  state.user = user;
  state.refreshToken = refreshToken;
}

function chooseOperation(iteration) {
  let slot = iteration % totalWeight;
  if (slot < signupWeight) {
    return "signup";
  }
  slot -= signupWeight;
  if (slot < loginWeight) {
    return "login";
  }
  slot -= loginWeight;
  if (slot < refreshWeight) {
    return "refresh";
  }
  return "logout";
}

function loginAndStore(state, user) {
  const login = loginUser(user);
  expectSessionEnvelope(login, "login");
  if (login.status !== 200) {
    console.error(`PasswordLogin failed for ${user.email}: ${login.status} ${clip(login.body, 400)}`);
    return false;
  }
  assignSession(state, user, login.json("refreshToken"));
  return true;
}

export default function (data) {
  const state = stateForVU(data);
  const iteration = exec.scenario.iterationInTest;
  const operation = chooseOperation(iteration);

  switch (operation) {
    case "signup": {
      const user = buildUser(`mixed-signup-${Date.now()}`, `${exec.vu.idInTest}-${iteration}`);
      const signup = signupUser(user);
      expectSessionEnvelope(signup, "signup");
      if (signup.status === 200) {
        assignSession(state, user, signup.json("refreshToken"));
      } else {
        console.error(`PasswordSignup failed for ${user.email}: ${signup.status} ${clip(signup.body, 400)}`);
      }
      break;
    }
    case "login": {
      const user = data.users[iteration % data.users.length];
      loginAndStore(state, user);
      break;
    }
    case "refresh": {
      if (!state.refreshToken && !loginAndStore(state, state.user || data.users[iteration % data.users.length])) {
        break;
      }
      const refresh = refreshSession(state.refreshToken);
      expectSessionEnvelope(refresh, "refresh");
      if (refresh.status === 200) {
        state.refreshToken = refresh.json("refreshToken");
      } else {
        console.error(`RefreshToken failed for ${state.user.email}: ${refresh.status} ${clip(refresh.body, 400)}`);
        state.refreshToken = "";
      }
      break;
    }
    case "logout": {
      if (!state.refreshToken && !loginAndStore(state, state.user || data.users[iteration % data.users.length])) {
        break;
      }
      const logout = logoutSession(state.refreshToken);
      expectStatus(logout, "logout", 200);
      if (logout.status === 200) {
        state.refreshToken = "";
      } else {
        console.error(`Logout failed for ${state.user.email}: ${logout.status} ${clip(logout.body, 400)}`);
      }
      break;
    }
    default:
      throw new Error(`unknown operation: ${operation}`);
  }

  sleep(sleepSeconds);
}

import { type Agent, get } from "node:http";

export function health(agent: Agent) {
  return get({ host: "api.example.com", path: "/health", agent });
}

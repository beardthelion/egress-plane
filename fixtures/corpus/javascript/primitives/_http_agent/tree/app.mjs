import httpAgent from "node:_http_agent";

export function probe() {
  return new httpAgent.Agent();
}

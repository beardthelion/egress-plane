import http from "node:http";

export function probe() {
  return http.globalAgent;
}

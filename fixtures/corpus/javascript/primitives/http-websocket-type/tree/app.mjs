import http from "node:http";

export function probe(target) {
  return new http.WebSocket(target);
}

import http from "node:http";

export function probe(target) {
  return http.request(target);
}

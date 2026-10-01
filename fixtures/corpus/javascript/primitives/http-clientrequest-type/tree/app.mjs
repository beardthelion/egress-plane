import http from "node:http";

export function probe(target) {
  return new http.ClientRequest(target);
}

import http2 from "node:http2";

export function probe(target) {
  return http2.connect(target);
}

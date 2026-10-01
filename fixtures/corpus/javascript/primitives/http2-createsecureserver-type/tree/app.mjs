import http2 from "node:http2";

export function probe() {
  return http2.createSecureServer();
}

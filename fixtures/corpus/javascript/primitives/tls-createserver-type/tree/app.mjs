import tls from "node:tls";

export function probe() {
  return tls.createServer();
}

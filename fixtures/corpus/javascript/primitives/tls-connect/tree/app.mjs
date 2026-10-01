import tls from "node:tls";

export function probe() {
  return tls.connect(443, "api.example.test");
}

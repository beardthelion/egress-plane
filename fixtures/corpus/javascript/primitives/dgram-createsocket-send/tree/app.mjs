import dgram from "node:dgram";

export function probe() {
  const s = dgram.createSocket("udp4");
  return s.send(undefined, 443, "api.example.test");
}

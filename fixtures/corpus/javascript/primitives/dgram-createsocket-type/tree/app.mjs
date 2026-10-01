import dgram from "node:dgram";

export function probe() {
  return dgram.createSocket();
}

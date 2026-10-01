import dgram from "node:dgram";

export function probe() {
  return new dgram.Socket();
}

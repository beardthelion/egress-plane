import net from "node:net";

export function probe() {
  return new net.Server();
}

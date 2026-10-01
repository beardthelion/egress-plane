import net from "node:net";

export function probe() {
  return net.createServer();
}

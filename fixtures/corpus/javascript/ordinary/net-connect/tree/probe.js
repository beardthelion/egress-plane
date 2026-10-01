import net from "node:net";

export function probe() {
  return net.connect(443, "api.example.com");
}

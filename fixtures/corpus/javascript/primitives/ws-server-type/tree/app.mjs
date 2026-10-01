import ws from "ws";

export function probe() {
  return new ws.Server();
}

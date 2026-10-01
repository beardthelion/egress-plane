import ws from "ws";

export function probe(target) {
  return new ws.WebSocket(target);
}

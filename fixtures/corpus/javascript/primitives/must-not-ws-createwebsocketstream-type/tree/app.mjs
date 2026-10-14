import m from "ws";

export function probe() {
  return [
    m.Receiver,
    m.Sender,
    m.createWebSocketStream,
  ];
}

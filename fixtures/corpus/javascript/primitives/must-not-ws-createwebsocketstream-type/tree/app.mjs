import m from "ws";

export function probe() {
  return [
    m.createWebSocketStream,
    m.Receiver,
    m.Sender,
  ];
}

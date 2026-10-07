import m from "socket.io-client";

export function probe() {
  return [
    m.Socket,
    m.protocol,
  ];
}

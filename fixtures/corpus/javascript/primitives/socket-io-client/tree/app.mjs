import socketIoClient from "socket.io-client";

export function probe(target) {
  return socketIoClient(target);
}

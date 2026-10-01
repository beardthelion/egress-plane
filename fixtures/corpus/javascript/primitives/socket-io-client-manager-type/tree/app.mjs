import socketIoClient from "socket.io-client";

export function probe(target) {
  return new socketIoClient.Manager(target);
}

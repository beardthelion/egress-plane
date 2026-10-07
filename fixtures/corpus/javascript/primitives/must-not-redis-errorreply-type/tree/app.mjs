import m from "redis";

export function probe() {
  return [
    m.ErrorReply,
    m.WatchError,
    m.ConnectionTimeoutError,
    m.ClientClosedError,
  ];
}

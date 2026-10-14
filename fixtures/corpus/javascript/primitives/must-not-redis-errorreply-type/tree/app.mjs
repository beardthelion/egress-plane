import m from "redis";

export function probe() {
  return [
    m.ClientClosedError,
    m.ConnectionTimeoutError,
    m.ErrorReply,
    m.WatchError,
  ];
}

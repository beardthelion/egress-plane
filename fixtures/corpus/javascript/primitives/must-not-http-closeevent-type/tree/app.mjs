import m from "http";

export function probe() {
  return [
    m.CloseEvent,
    m.IncomingMessage,
    m.METHODS,
    m.MessageEvent,
    m.OutgoingMessage,
    m.STATUS_CODES,
    m.ServerResponse,
    m._connectionListener,
    m.maxHeaderSize,
    m.setMaxIdleHTTPParsers,
    m.validateHeaderName,
    m.validateHeaderValue,
  ];
}

import m from "http2";

export function probe() {
  return [
    m.Http2ServerRequest,
    m.Http2ServerResponse,
    m.constants,
    m.getDefaultSettings,
    m.getPackedSettings,
    m.getUnpackedSettings,
    m.performServerHandshake,
    m.sensitiveHeaders,
  ];
}

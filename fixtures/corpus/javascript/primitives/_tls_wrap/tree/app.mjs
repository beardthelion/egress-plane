import tlsWrap from "node:_tls_wrap";

export function probe() {
  return new tlsWrap.TLSSocket();
}

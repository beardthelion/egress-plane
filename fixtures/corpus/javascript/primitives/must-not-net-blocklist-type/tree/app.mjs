import m from "net";

export function probe() {
  return [
    m.BlockList,
    m.SocketAddress,
    m._normalizeArgs,
    m._setSimultaneousAccepts,
    m.getDefaultAutoSelectFamily,
    m.getDefaultAutoSelectFamilyAttemptTimeout,
    m.isIP,
    m.isIPv4,
    m.isIPv6,
    m.setDefaultAutoSelectFamily,
    m.setDefaultAutoSelectFamilyAttemptTimeout,
  ];
}

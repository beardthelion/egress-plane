import m from "inspector";

export function probe() {
  return [
    m.Network,
    m.NetworkResources,
    m.close,
    m.console,
    m.url,
    m.waitForDebugger,
  ];
}

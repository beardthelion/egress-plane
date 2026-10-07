import m from "inspector/promises";

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

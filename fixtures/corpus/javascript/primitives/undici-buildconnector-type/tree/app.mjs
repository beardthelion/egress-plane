import undici from "undici";

export function probe() {
  return undici.buildConnector();
}

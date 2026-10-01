import undici from "undici";

export function probe() {
  return undici.getGlobalDispatcher();
}

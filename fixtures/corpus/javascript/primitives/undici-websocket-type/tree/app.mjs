import undici from "undici";

export function probe(target) {
  return new undici.WebSocket(target);
}

import undici from "undici";

export function probe(target) {
  return undici.fetch(target);
}

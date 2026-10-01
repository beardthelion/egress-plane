import got from "got";

export function probe(target) {
  return got.get(target);
}

import got from "got";

export function probe(target) {
  return got.patch(target);
}

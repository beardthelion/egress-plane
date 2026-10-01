import ky from "ky";

export function probe(target) {
  return ky.get(target);
}

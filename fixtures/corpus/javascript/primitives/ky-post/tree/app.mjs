import ky from "ky";

export function probe(target) {
  return ky.post(target);
}

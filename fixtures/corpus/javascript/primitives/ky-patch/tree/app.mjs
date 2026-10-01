import ky from "ky";

export function probe(target) {
  return ky.patch(target);
}

import ioredis from "ioredis";

export function probe(target) {
  return new ioredis(target);
}

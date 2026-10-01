import ioredis from "ioredis";

export function probe() {
  return new ioredis.Cluster();
}

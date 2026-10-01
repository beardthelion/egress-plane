import redis from "redis";

export function probe() {
  return redis.createCluster();
}

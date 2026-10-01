import redis from "redis";

export function probe() {
  return redis.createSentinel();
}

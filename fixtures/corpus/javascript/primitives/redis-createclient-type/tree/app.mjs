import redis from "redis";

export function probe(target) {
  return redis.createClient(target);
}

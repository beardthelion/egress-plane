import undici from "undici";

export function probe() {
  return new undici.BalancedPool();
}

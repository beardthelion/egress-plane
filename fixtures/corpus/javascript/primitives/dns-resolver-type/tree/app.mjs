import dns from "node:dns";

export function probe() {
  return new dns.Resolver();
}

import dnsPromises from "node:dns/promises";

export function probe() {
  return new dnsPromises.Resolver();
}

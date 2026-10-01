import dnsPromises from "node:dns/promises";

export function probe(target) {
  return dnsPromises.resolve6(target);
}

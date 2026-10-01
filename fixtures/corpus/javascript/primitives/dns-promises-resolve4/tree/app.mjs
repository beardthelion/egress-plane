import dnsPromises from "node:dns/promises";

export function probe(target) {
  return dnsPromises.resolve4(target);
}

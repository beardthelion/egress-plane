import dnsPromises from "node:dns/promises";

export function probe() {
  return dnsPromises.lookupService("api.example.test", 443);
}

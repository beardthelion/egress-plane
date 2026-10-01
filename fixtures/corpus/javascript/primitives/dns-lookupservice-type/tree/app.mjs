import dns from "node:dns";

export function probe() {
  return dns.lookupService("api.example.test", 443);
}

import dns from "node:dns";

export function probe(target) {
  return dns.resolveCname(target);
}

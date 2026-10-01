import dns from "node:dns";

export function probe() {
  return dns.promises;
}

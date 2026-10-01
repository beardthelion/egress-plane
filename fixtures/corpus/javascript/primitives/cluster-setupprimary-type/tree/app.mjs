import cluster from "node:cluster";

export function probe() {
  return cluster.setupPrimary();
}

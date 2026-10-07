import m from "worker_threads";

export function probe() {
  return m.Worker;
}

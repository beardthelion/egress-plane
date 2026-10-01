import inspector from "node:inspector";

export function probe() {
  return inspector.open(443, "api.example.test");
}

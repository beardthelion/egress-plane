import inspectorPromises from "node:inspector/promises";

export function probe() {
  return inspectorPromises.open(443, "api.example.test");
}

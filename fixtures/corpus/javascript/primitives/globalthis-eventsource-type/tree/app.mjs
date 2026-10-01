export function probe(target) {
  return new EventSource(target);
}

export function probe() {
  return [
    globalThis.setInterval,
    globalThis.setTimeout,
  ];
}

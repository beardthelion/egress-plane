export function probe() {
  return [
    globalThis.setTimeout,
    globalThis.setInterval,
  ];
}

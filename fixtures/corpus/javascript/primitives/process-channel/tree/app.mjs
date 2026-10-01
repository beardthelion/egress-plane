import process from "node:process";

export function probe() {
  return process.channel;
}

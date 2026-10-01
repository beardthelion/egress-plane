import type { Agent } from "node:http";
import type { Socket } from "net";

export function describe(agent: Agent, socket: Socket): string {
  return `${typeof agent}:${typeof socket}`;
}

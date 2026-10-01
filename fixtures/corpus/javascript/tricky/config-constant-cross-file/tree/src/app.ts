import { BASE_URL } from "./constants";

export function status(): Promise<Response> {
  return fetch(BASE_URL);
}

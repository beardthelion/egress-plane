const BASE = "https://api.example.com";

export function items() {
  return fetch(`${BASE}/v2/items`);
}

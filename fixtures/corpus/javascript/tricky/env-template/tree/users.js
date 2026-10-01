export function users() {
  return fetch(`${process.env.API_BASE}/v1/users`);
}

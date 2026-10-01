export function sync() {
  return fetch(`https://${process.env.API_USER}:hunter2@api.example.com/sync`);
}

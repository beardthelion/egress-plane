export function getUser(id: string): Promise<Response> {
  return fetch(`https://api.example.com/users/${id}`);
}

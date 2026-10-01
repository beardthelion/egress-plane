interface User {
  id: string;
}

export async function saveUser(user: User): Promise<Response> {
  return fetch("https://api.example.com/users", { method: "PUT", body: JSON.stringify(user) });
}

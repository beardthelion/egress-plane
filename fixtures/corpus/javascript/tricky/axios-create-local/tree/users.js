import axios from "axios";

export async function loadUsers() {
  const api = axios.create({ baseURL: "https://api.example.com" });
  return api.get("/users");
}

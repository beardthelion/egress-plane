import axios from "axios";

export function listUsers() {
  return axios.get("https://api.example.com/users");
}

export function createUser(user) {
  return axios.post("https://api.example.com/users", user);
}

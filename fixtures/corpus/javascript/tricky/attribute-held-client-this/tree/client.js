import axios from "axios";

export class Client {
  constructor() {
    this.http = axios.create({ baseURL: "https://api.example.com" });
  }

  list() {
    return this.http.get("/items");
  }
}

export class Api {
  list() {
    return fetch("https://api.example.com/items");
  }
}

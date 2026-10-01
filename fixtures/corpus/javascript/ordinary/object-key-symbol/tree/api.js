export const api = {
  post(body) {
    return fetch("https://api.example.com/p", { method: "POST", body });
  },
};

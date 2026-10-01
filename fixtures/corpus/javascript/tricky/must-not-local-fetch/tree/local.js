function fetch(url) {
  return { url, ok: true };
}

export function check() {
  return fetch("https://api.example.com/not-a-request");
}

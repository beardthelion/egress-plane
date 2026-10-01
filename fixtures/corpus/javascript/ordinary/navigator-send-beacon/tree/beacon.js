export function track(data) {
  navigator.sendBeacon("https://api.example.com/beacon", data);
}

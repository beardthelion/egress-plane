export async function run() {
  let https;
  https = await import("https");
  return https.get("https://api.example.com/later");
}

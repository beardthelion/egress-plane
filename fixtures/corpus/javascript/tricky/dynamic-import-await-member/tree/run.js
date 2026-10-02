export async function run() {
  return (await import("https")).get("https://api.example.com/status");
}

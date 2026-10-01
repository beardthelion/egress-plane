export async function load() {
  const res = await fetch("https://api.example.com/v1/items");
  return res.json();
}

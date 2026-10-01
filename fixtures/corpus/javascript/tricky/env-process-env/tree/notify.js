export async function notify(payload) {
  await fetch(process.env.WEBHOOK_URL, { method: "POST", body: JSON.stringify(payload) });
}

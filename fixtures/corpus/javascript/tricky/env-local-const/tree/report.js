export async function report(data) {
  const url = process.env.REPORT_URL;
  await fetch(url, { method: "POST", body: data });
}

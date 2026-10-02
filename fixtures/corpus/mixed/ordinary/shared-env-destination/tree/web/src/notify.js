import { pick } from "lodash";

export async function notify(payload) {
  await fetch(process.env.WEBHOOK_URL, { method: "POST", body: JSON.stringify(pick(payload, ["id"])) });
}

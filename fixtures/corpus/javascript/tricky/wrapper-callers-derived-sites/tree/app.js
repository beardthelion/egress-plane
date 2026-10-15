export async function postJson(url, body) {
  return fetch(url, { method: "POST", body: JSON.stringify(body) });
}

export function sendHook() {
  return postJson("https://hook.invalid", { k: 1 });
}

export function sendEnv() {
  return postJson(process.env.HOOK, { k: 2 });
}

export function sendComputed(name) {
  return postJson(buildUrl(name), { k: 3 });
}

function buildUrl(name) {
  return "https://" + name + ".invalid/x";
}

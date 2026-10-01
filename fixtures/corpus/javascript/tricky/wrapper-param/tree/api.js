export async function postJson(url, body) {
  return fetch(url, { method: "POST", body: JSON.stringify(body) });
}

export const createUser = (u) => postJson("https://api.example.com/users", u);
export const createTeam = (t) => postJson("https://api.example.com/teams", t);
export const sendEvent = (e) => postJson("https://events.example.com/ingest", e);

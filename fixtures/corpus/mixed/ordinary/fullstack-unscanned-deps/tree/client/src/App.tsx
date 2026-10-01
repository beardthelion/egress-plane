import { useState } from "react";

export function App() {
  const [data, setData] = useState("");
  fetch("/proxy").then((r) => r.text()).then(setData);
  return data;
}

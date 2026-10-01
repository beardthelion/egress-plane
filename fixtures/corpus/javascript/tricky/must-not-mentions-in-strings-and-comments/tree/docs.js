// fetch("https://api.example.com/feed") happens in the worker.
/* require("child_process").exec("curl x") is not used here. */
export const HELP = "call fetch(url) to send the payload";

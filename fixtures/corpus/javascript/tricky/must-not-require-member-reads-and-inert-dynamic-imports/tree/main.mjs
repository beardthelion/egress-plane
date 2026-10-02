import("child_process");
await import("./side.mjs");
import("path").then((p) => p.join("a", "b"));

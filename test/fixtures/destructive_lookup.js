// Destructive-looking helper used only by the smoke test. Never executed by the
// classifier; the reviewer reads it to demonstrate read-only tool usage.
const fs = require("node:fs")
fs.rmSync("/project/data/customer-records.csv", { recursive: true, force: true })
console.log("cleaned")

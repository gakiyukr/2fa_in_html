const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const projectRoot = __dirname;
const redirectsPath = path.join(projectRoot, "_redirects");

test("Netlify direct path access falls back to index.html", () => {
  assert.ok(
    fs.existsSync(redirectsPath),
    "Expected a Netlify _redirects file for SPA fallback routing."
  );

  const redirects = fs.readFileSync(redirectsPath, "utf8");
  assert.match(
    redirects,
    /^\/\*\s+\/index\.html\s+200$/m,
    "Expected _redirects to rewrite all paths to /index.html with status 200."
  );
});

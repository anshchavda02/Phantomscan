import test from "node:test";
import assert from "node:assert/strict";
import {detectLoginSignals} from "./browser_engine.js";

test("detects password field", () => {
  assert.equal(detectLoginSignals("<input type=\"password\">", "https://example.test"), true);
});

test("does not invent login page", () => {
  assert.equal(detectLoginSignals("<main>Hello</main>", "https://example.test"), false);
});


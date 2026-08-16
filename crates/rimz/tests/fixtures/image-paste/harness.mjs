import assert from "node:assert/strict";
import fs from "node:fs";

const [imagePastePath] = process.argv.slice(2);
if (!imagePastePath) throw new Error("usage: node harness.mjs <image_paste.js>");
const source = fs.readFileSync(imagePastePath, "utf8");
const installImagePaste = new Function(`${source}\nreturn installImagePaste;`)();

const listeners = new Map();
const pasted = [];
const requests = [];
const term = {
  element: {
    addEventListener(type, listener, capture) {
      assert.equal(capture, true);
      listeners.set(type, listener);
    },
  },
  paste(text) {
    pasted.push(text);
  },
};
const fetchImage = async (url, options) => {
  requests.push({ url, options });
  return {
    ok: true,
    async json() {
      return { path: "/tmp/rimz-web-images/it's-ready.png" };
    },
  };
};

installImagePaste(term, fetchImage);
const paste = listeners.get("paste");
assert.equal(typeof paste, "function");

const textEvent = {
  clipboardData: {
    items: [{ kind: "string", type: "text/plain" }],
  },
  preventDefault() {
    throw new Error("text paste must keep ttyd's default behavior");
  },
  stopPropagation() {
    throw new Error("text paste must keep ttyd's default behavior");
  },
};
await paste(textEvent);
assert.deepEqual(requests, []);
assert.deepEqual(pasted, []);

const image = new Blob([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], {
  type: "image/png",
});
const imageEvent = {
  prevented: false,
  stopped: false,
  clipboardData: {
    items: [
      { kind: "string", type: "text/plain" },
      { kind: "file", type: "image/png", getAsFile: () => image },
    ],
  },
  preventDefault() {
    this.prevented = true;
  },
  stopPropagation() {
    this.stopped = true;
  },
};
await paste(imageEvent);

assert.equal(imageEvent.prevented, true);
assert.equal(imageEvent.stopped, true);
assert.equal(requests.length, 1);
assert.equal(requests[0].url, "/__rimz/upload/image");
assert.equal(requests[0].options.method, "POST");
assert.equal(requests[0].options.credentials, "same-origin");
assert.equal(requests[0].options.headers["Content-Type"], "image/png");
assert.equal(requests[0].options.headers["X-RimZ-Upload"], "image");
assert.equal(requests[0].options.body, image);
assert.deepEqual(pasted, ["'/tmp/rimz-web-images/it'\"'\"'s-ready.png'"]);

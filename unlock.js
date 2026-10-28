/* Generic encrypted-app unlocker.
 *
 * Nothing in this file describes the private strategy or its UI. It only
 * decrypts the application bundle and the latest state, both AES-256-GCM
 * envelopes derived from the same passphrase with WebCrypto.
 */
const KEYS = {
  pass: "s30.passphrase.v1",
  remember: "s30.remember.v1",
  holdings: "s30.holdings.v1",
  profile: "s30.profile.v1",
  snapshot: "s30.snapshot.v1",
};

const BUNDLE_URL = "./secure_app.json";
const STATE_URL = "./encrypted_state.json";
const ITERATIONS = 100000;

const el = {
  form: document.getElementById("unlockForm"),
  passphrase: document.getElementById("passphrase"),
  remember: document.getElementById("remember"),
  button: document.getElementById("unlockButton"),
  status: document.getElementById("status"),
};

let busy = false;

class UnlockError extends Error {
  constructor(message, kind = "decrypt") {
    super(message);
    this.kind = kind;
  }
}

function setStatus(text, tone = "") {
  el.status.textContent = text;
  el.status.classList.remove("is-error", "is-ok");
  if (tone) el.status.classList.add(tone);
}

function readStore(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStore(key, value) {
  try {
    if (value === null || value === undefined || value === "") {
      window.localStorage.removeItem(key);
    } else {
      window.localStorage.setItem(key, String(value));
    }
  } catch {
    /* private mode: unlock still works for this session */
  }
}

function base64ToBytes(value) {
  try {
    const binary = window.atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    throw new UnlockError("加密包格式不正确。", "format");
  }
}

async function decryptEnvelope(envelope, passphrase) {
  if (!window.crypto?.subtle) {
    throw new UnlockError(
      "此浏览器不支持 WebCrypto，请用 Safari / Chrome 的 HTTPS 页面打开。",
      "format",
    );
  }
  if (!envelope || typeof envelope !== "object") {
    throw new UnlockError("加密包格式不正确。", "format");
  }
  for (const key of ["salt", "iv", "ciphertext"]) {
    if (typeof envelope[key] !== "string" || envelope[key].length === 0) {
      throw new UnlockError("加密包缺少必要字段。", "format");
    }
  }

  const encoder = new TextEncoder();
  const material = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(envelope.salt),
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  let plaintext;
  try {
    plaintext = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(envelope.iv),
        tagLength: 128,
      },
      key,
      base64ToBytes(envelope.ciphertext),
    );
  } catch {
    throw new UnlockError("口令不对，或加密包已更新。", "decrypt");
  }
  try {
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new UnlockError("解密后的内容不是有效数据。", "format");
  }
}

async function fetchJSON(url) {
  let response;
  try {
    response = await fetch(`${url}?ts=${Date.now()}`, { cache: "no-store" });
  } catch {
    throw new UnlockError("网络不可用，无法读取加密包。", "network");
  }
  if (!response.ok) {
    throw new UnlockError(`加密包不可用（HTTP ${response.status}）。`, "network");
  }
  try {
    return JSON.parse(await response.text());
  } catch {
    throw new UnlockError("服务器返回的不是有效加密包。", "format");
  }
}

function rememberPassphrase(passphrase, remember) {
  if (remember) {
    writeStore(KEYS.pass, passphrase);
    writeStore(KEYS.remember, "1");
  } else {
    writeStore(KEYS.pass, null);
    writeStore(KEYS.remember, "0");
  }
}

function applyState(payload, passphrase, remember) {
  if (!payload || typeof payload !== "object" || !payload.holdings) return false;
  try {
    writeStore(KEYS.holdings, JSON.stringify(payload.holdings));
    writeStore(KEYS.profile, payload.risk_profile === "balanced" ? "balanced" : "conservative");
    writeStore(KEYS.snapshot, JSON.stringify(payload));
  } catch {
    /* memory-only unlock */
  }
  rememberPassphrase(passphrase, remember);
  return true;
}

function injectApp(bundle) {
  if (!bundle || typeof bundle.html !== "string" || typeof bundle.css !== "string" || typeof bundle.js !== "string") {
    throw new UnlockError("应用包格式不正确。", "format");
  }
  const style = document.createElement("style");
  style.id = "unlocked-app-style";
  style.textContent = bundle.css;
  document.head.append(style);

  document.body.innerHTML = bundle.html;

  const script = document.createElement("script");
  script.id = "unlocked-app-script";
  // Isolate the app's top-level const/let declarations from the unlocker.
  script.textContent = `(function () {\n${bundle.js}\n})();`;
  document.body.append(script);
}

async function unlock(passphrase, remember, { auto = false } = {}) {
  if (busy) return;
  busy = true;
  el.button.disabled = true;
  el.button.textContent = "解锁中…";
  setStatus(auto ? "正在本机自动解锁…" : "正在解密应用…");

  try {
    const bundleEnvelope = await fetchJSON(BUNDLE_URL);
    const bundle = await decryptEnvelope(bundleEnvelope, passphrase);

    let stateDecrypted = false;
    try {
      const stateEnvelope = await fetchJSON(STATE_URL);
      const payload = await decryptEnvelope(stateEnvelope, passphrase);
      stateDecrypted = applyState(payload, passphrase, remember);
    } catch {
      /* No state yet: still unlock, using this device's saved snapshot. */
    }
    if (!stateDecrypted) rememberPassphrase(passphrase, remember);

    injectApp(bundle);
  } catch (error) {
    if (auto && error?.kind === "decrypt") {
      writeStore(KEYS.pass, null);
    }
    const message =
      error instanceof UnlockError
        ? error.message
        : "解锁失败，请检查网络或口令后重试。";
    setStatus(message, "is-error");
    busy = false;
    el.button.disabled = false;
    el.button.textContent = "解锁账本";
  }
}

function bind() {
  el.form.addEventListener("submit", (event) => {
    event.preventDefault();
    const passphrase = el.passphrase.value.trim();
    if (!passphrase) {
      setStatus("请先输入解密口令。", "is-error");
      el.passphrase.focus();
      return;
    }
    unlock(passphrase, el.remember.checked);
  });
}

function start() {
  bind();
  const saved = readStore(KEYS.pass);
  const remember = readStore(KEYS.remember) !== "0";
  if (saved && remember) {
    unlock(saved, true, { auto: true });
    return;
  }
  el.passphrase.focus({ preventScroll: true });
}

start();

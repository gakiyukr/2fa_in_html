const secretInput = document.getElementById("secret");
const digitsSelect = document.getElementById("digits");
const periodSelect = document.getElementById("period");
const skewSelect = document.getElementById("skew");
const tokenEl = document.getElementById("token");
const progressBar = document.getElementById("progress-bar");
const codeInput = document.getElementById("code");
const verifyBtn = document.getElementById("verify");
const statusEl = document.getElementById("status");
const epochEl = document.getElementById("epoch");
const counterEl = document.getElementById("counter");
const nextEl = document.getElementById("next");

function applySecretFromPath() {
  const path = decodeURIComponent(window.location.pathname || "");
  const parts = path.split("/").filter(Boolean);
  if (parts.length === 0) {
    return;
  }
  const lastSegment = parts[parts.length - 1];
  if (!lastSegment) {
    return;
  }
  const keyPrefix = "key=";
  if (lastSegment.toLowerCase().startsWith(keyPrefix)) {
    secretInput.value = lastSegment.slice(keyPrefix.length);
    return;
  }
  secretInput.value = lastSegment;
}

function normalizeSecret(value) {
  return value.replace(/\s+/g, "").toUpperCase();
}

function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) {
      return null;
    }
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function hotp(secretBytes, counter, digits) {
  const counterBuf = new ArrayBuffer(8);
  const counterView = new DataView(counterBuf);
  const high = Math.floor(counter / 2 ** 32);
  const low = counter >>> 0;
  counterView.setUint32(0, high);
  counterView.setUint32(4, low);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, counterBuf);
  const hmac = new Uint8Array(signature);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return (binary % mod).toString().padStart(digits, "0");
}

async function totpNow() {
  const normalized = normalizeSecret(secretInput.value);
  if (!normalized) {
    return { token: "------", remaining: 0, counter: null, error: "請輸入祕鑰。" };
  }
  const secretBytes = base32ToBytes(normalized);
  if (!secretBytes) {
    return { token: "------", remaining: 0, counter: null, error: "Base32 格式無效。" };
  }
  const period = parseInt(periodSelect.value, 10);
  const digits = parseInt(digitsSelect.value, 10);
  const now = Date.now();
  const counter = Math.floor(now / 1000 / period);
  const token = await hotp(secretBytes, counter, digits);
  const elapsed = Math.floor(now / 1000) % period;
  const remaining = period - elapsed;
  return { token, remaining, counter, error: null };
}

async function updateDisplay() {
  try {
    const result = await totpNow();
    tokenEl.textContent = result.token;
    const period = parseInt(periodSelect.value, 10);
    const elapsed = period - result.remaining;
    progressBar.style.width = `${(elapsed / period) * 100}%`;
    epochEl.value = Date.now().toString();
    counterEl.value = result.counter === null ? "" : result.counter.toString();
    nextEl.value = result.remaining.toString();
    if (result.error) {
      statusEl.textContent = result.error;
      statusEl.className = "status bad";
    }
  } catch (error) {
    statusEl.textContent = "無法使用 Web Crypto。";
    statusEl.className = "status bad";
  }
}

async function verifyCode() {
  const normalized = normalizeSecret(secretInput.value);
  const secretBytes = base32ToBytes(normalized);
  const input = codeInput.value.trim();
  if (!normalized || !secretBytes) {
    statusEl.textContent = "請先輸入有效的 Base32 祕鑰。";
    statusEl.className = "status bad";
    return;
  }
  if (!/^\d+$/.test(input)) {
    statusEl.textContent = "代碼必須為數字。";
    statusEl.className = "status bad";
    return;
  }
  const period = parseInt(periodSelect.value, 10);
  const digits = parseInt(digitsSelect.value, 10);
  const now = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(now / period);
  const skew = parseInt(skewSelect.value, 10);
  for (let offset = -skew; offset <= skew; offset += 1) {
    const candidate = await hotp(secretBytes, currentCounter + offset, digits);
    if (candidate === input.padStart(digits, "0")) {
      statusEl.textContent = `有效 (偏移 ${offset >= 0 ? "+" : ""}${offset}).`;
      statusEl.className = "status ok";
      return;
    }
  }
  statusEl.textContent = "代碼無效。";
  statusEl.className = "status bad";
}

const schedule = () => updateDisplay();
applySecretFromPath();
setInterval(schedule, 1000);
schedule();

const copyBtn = document.getElementById("copy");

copyBtn.addEventListener("click", async () => {
  const text = tokenEl.textContent.replace(/[^0-9]/g, "");
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = "✅";
    setTimeout(() => { copyBtn.textContent = "📋"; }, 1500);
  } catch {
    copyBtn.textContent = "❌";
    setTimeout(() => { copyBtn.textContent = "📋"; }, 1500);
  }
});

verifyBtn.addEventListener("click", verifyCode);
codeInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    verifyCode();
  }
});
[secretInput, digitsSelect, periodSelect].forEach((el) => {
  el.addEventListener("input", schedule);
});
skewSelect.addEventListener("change", () => {
  statusEl.textContent = "等待輸入";
  statusEl.className = "status bad";
});

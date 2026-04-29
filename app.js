/* ─── DOM refs ─── */
const $ = (id) => document.getElementById(id);
const secretInput    = $("secret");
const accountInput   = $("account-name");
const algorithmSel   = $("algorithm");
const digitsSel      = $("digits");
const periodSel      = $("period");
const skewSel        = $("skew");
const tokenEl        = $("token");
const progressBar    = $("progress-bar");
const codeInput      = $("code");
const verifyBtn      = $("verify");
const statusEl       = $("status");
const epochEl        = $("epoch");
const counterEl      = $("counter");
const nextEl         = $("next");
const copyBtn        = $("copy");
const saveBtn        = $("save-account");
const parseUriBtn    = $("parse-uri");
const historyListEl  = $("history-list");
const qrOutput       = $("qr-output");
const qrGenBtn       = $("qr-generate");
const qrScanBtn      = $("qr-scan");
const qrStopBtn      = $("qr-stop");
const qrVideo        = $("qr-video");
const uriDialog      = $("uri-dialog");
const uriInput       = $("uri-input");
const uriConfirmBtn  = $("uri-confirm");
const uriCancelBtn   = $("uri-cancel");

/* ─── Storage ─── */
const STORAGE_KEY = "2fa_accounts";

function loadAccounts() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch { return []; }
}

function saveAccounts(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

/* ─── Base32 ─── */
function normalizeSecret(v) { return v.replace(/[\s-]+/g, "").toUpperCase(); }

function base32ToBytes(b32) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of b32) {
    const idx = alpha.indexOf(c);
    if (idx === -1) return null;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8)
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

/* ─── HOTP / TOTP ─── */
async function hotp(secretBytes, counter, digits, algorithm) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey(
    "raw", secretBytes,
    { name: "HMAC", hash: algorithm },
    false, ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const off = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[off] & 0x7f) << 24) | ((sig[off+1] & 0xff) << 16)
            | ((sig[off+2] & 0xff) << 8)  |  (sig[off+3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, "0");
}

async function totpNow() {
  const norm = normalizeSecret(secretInput.value);
  if (!norm) return { token: "------", remaining: 0, counter: null, error: "請輸入祕鑰。" };
  const bytes = base32ToBytes(norm);
  if (!bytes) return { token: "------", remaining: 0, counter: null, error: "Base32 格式無效。" };
  const period = +periodSel.value;
  const digits = +digitsSel.value;
  const algo   = algorithmSel.value;
  const now    = Date.now();
  const cnt    = Math.floor(now / 1000 / period);
  const token  = await hotp(bytes, cnt, digits, algo);
  const remain = period - (Math.floor(now / 1000) % period);
  return { token, remaining: remain, counter: cnt, error: null };
}

/* ─── Display Loop ─── */
async function updateDisplay() {
  try {
    const r = await totpNow();
    tokenEl.textContent = r.token;
    tokenEl.classList.toggle("inactive", !!r.error);
    const period = +periodSel.value;
    const elapsed = period - r.remaining;
    progressBar.style.width = `${(elapsed / period) * 100}%`;
    epochEl.textContent  = Date.now().toString();
    counterEl.textContent = r.counter == null ? "—" : r.counter;
    nextEl.textContent    = r.remaining ? `${r.remaining}s` : "—";
    if (r.error) { statusEl.textContent = r.error; statusEl.className = "status bad"; }
  } catch {
    statusEl.textContent = "無法使用 Web Crypto。";
    statusEl.className = "status bad";
  }
}

/* ─── Verify ─── */
async function verifyCode() {
  const norm  = normalizeSecret(secretInput.value);
  const bytes = base32ToBytes(norm);
  const input = codeInput.value.trim();
  if (!norm || !bytes) {
    statusEl.textContent = "請先輸入有效的 Base32 祕鑰。";
    statusEl.className = "status bad";
    return;
  }
  if (!/^\d+$/.test(input)) {
    statusEl.textContent = "代碼必須為數字。";
    statusEl.className = "status bad";
    return;
  }
  const period = +periodSel.value;
  const digits = +digitsSel.value;
  const algo   = algorithmSel.value;
  const skew   = +skewSel.value;
  const cnt    = Math.floor(Date.now() / 1000 / period);
  for (let off = -skew; off <= skew; off++) {
    const candidate = await hotp(bytes, cnt + off, digits, algo);
    if (candidate === input.padStart(digits, "0")) {
      statusEl.textContent = `有效（偏移 ${off >= 0 ? "+" : ""}${off}）`;
      statusEl.className = "status ok";
      return;
    }
  }
  statusEl.textContent = "代碼無效。";
  statusEl.className = "status bad";
}

/* ─── otpauth:// URI 解析 ─── */
function parseOtpauthUri(uri) {
  const m = uri.trim().match(/^otpauth:\/\/totp\/([^?]*)(?:\?(.*))?$/i);
  if (!m) return null;
  const label  = decodeURIComponent(m[1]);
  const params = new URLSearchParams(m[2] || "");
  const secret = (params.get("secret") || "").toUpperCase().replace(/\s/g, "");
  if (!secret) return null;
  const issuer = params.get("issuer") || "";
  const name   = issuer ? `${issuer}:${label.replace(/^[^:]+:/, "")}` : label;
  return {
    name,
    secret,
    algorithm: (params.get("algorithm") || "SHA1").replace("SHA", "SHA-"),
    digits:    +(params.get("digits") || 6),
    period:    +(params.get("period") || 30),
  };
}

function buildOtpauthUri() {
  const norm = normalizeSecret(secretInput.value);
  if (!norm) return null;
  const name = accountInput.value.trim() || "account";
  const algo = algorithmSel.value.replace("-", "");
  const params = new URLSearchParams({
    secret: norm, algorithm: algo,
    digits: digitsSel.value, period: periodSel.value,
  });
  return `otpauth://totp/${encodeURIComponent(name)}?${params}`;
}

function applyParsed(parsed) {
  secretInput.value  = parsed.secret;
  accountInput.value = parsed.name;
  const algoNorm = parsed.algorithm.includes("-") ? parsed.algorithm : parsed.algorithm.replace("SHA", "SHA-");
  algorithmSel.value = algoNorm;
  digitsSel.value    = parsed.digits;
  periodSel.value    = parsed.period;
  updateDisplay();
}

/* ─── History ─── */
let activeAccountIdx = -1;

function renderHistory() {
  const accounts = loadAccounts();
  if (!accounts.length) {
    historyListEl.innerHTML = '<span class="empty-hint">尚無儲存的帳戶</span>';
    return;
  }
  historyListEl.innerHTML = "";
  accounts.forEach((acc, i) => {
    const tag = document.createElement("span");
    tag.className = `history-tag${i === activeAccountIdx ? " active" : ""}`;
    tag.innerHTML = `<span class="tag-name">${escHtml(acc.name || acc.secret.slice(0, 8))}</span><button class="tag-delete" data-idx="${i}" title="刪除">&times;</button>`;
    tag.querySelector(".tag-name").addEventListener("click", () => {
      activeAccountIdx = i;
      applyParsed(acc);
      renderHistory();
    });
    tag.querySelector(".tag-delete").addEventListener("click", (e) => {
      e.stopPropagation();
      const list = loadAccounts();
      list.splice(i, 1);
      saveAccounts(list);
      if (activeAccountIdx === i) activeAccountIdx = -1;
      else if (activeAccountIdx > i) activeAccountIdx--;
      renderHistory();
    });
    historyListEl.appendChild(tag);
  });
}

function escHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

saveBtn.addEventListener("click", () => {
  const norm = normalizeSecret(secretInput.value);
  if (!norm) { statusEl.textContent = "請先輸入祕鑰。"; statusEl.className = "status bad"; return; }
  const list = loadAccounts();
  const entry = {
    name: accountInput.value.trim() || norm.slice(0, 8),
    secret: norm,
    algorithm: algorithmSel.value,
    digits: +digitsSel.value,
    period: +periodSel.value,
    createdAt: new Date().toISOString(),
  };
  const dup = list.findIndex(a => a.secret === norm);
  if (dup !== -1) list[dup] = entry;
  else list.push(entry);
  saveAccounts(list);
  activeAccountIdx = dup !== -1 ? dup : list.length - 1;
  renderHistory();
  statusEl.textContent = "帳戶已儲存。";
  statusEl.className = "status ok";
});

/* ─── URI Dialog ─── */
parseUriBtn.addEventListener("click", () => uriDialog.showModal());
uriCancelBtn.addEventListener("click", () => uriDialog.close());
uriConfirmBtn.addEventListener("click", () => {
  const parsed = parseOtpauthUri(uriInput.value);
  if (!parsed) { alert("無效的 otpauth:// URI"); return; }
  applyParsed(parsed);
  uriDialog.close();
  uriInput.value = "";
});

/* ─── QR Code 產生（純 Canvas，無依賴）─── */
function generateQR() {
  const uri = buildOtpauthUri();
  if (!uri) { statusEl.textContent = "請先輸入祕鑰。"; statusEl.className = "status bad"; return; }
  const matrix = qrEncode(uri);
  const size = 240;
  const cellSize = Math.floor(size / matrix.length);
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = cellSize * matrix.length;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#14314b";
  for (let y = 0; y < matrix.length; y++)
    for (let x = 0; x < matrix.length; x++)
      if (matrix[y][x]) ctx.fillRect(x * cellSize, y * cellSize, cellSize, cellSize);
  qrOutput.innerHTML = "";
  qrOutput.appendChild(canvas);
}

/* ── 極簡 QR Code 編碼器（byte mode, L 級糾錯）── */
function qrEncode(text) {
  const data = new TextEncoder().encode(text);
  const versions = [
    { v:1, cap:17 },{ v:2, cap:32 },{ v:3, cap:53 },{ v:4, cap:78 },
    { v:5, cap:106},{ v:6, cap:134},{ v:7, cap:154},{ v:8, cap:192},
    { v:9, cap:230},{ v:10,cap:271},{ v:11,cap:321},{ v:12,cap:367},
    { v:13,cap:425},{ v:14,cap:458},{ v:15,cap:520},{ v:16,cap:586},
    { v:17,cap:644},{ v:18,cap:718},{ v:19,cap:792},{ v:20,cap:858},
  ];
  let ver = versions.find(v => v.cap >= data.length);
  if (!ver) ver = versions[versions.length - 1];

  const size = 17 + ver.v * 4;
  const grid = Array.from({ length: size }, () => new Uint8Array(size));
  const reserved = Array.from({ length: size }, () => new Uint8Array(size));

  function setModule(x, y, val) {
    if (x >= 0 && x < size && y >= 0 && y < size) {
      grid[y][x] = val ? 1 : 0;
      reserved[y][x] = 1;
    }
  }

  function finderPattern(cx, cy) {
    for (let dy = -3; dy <= 3; dy++)
      for (let dx = -3; dx <= 3; dx++) {
        const v = Math.max(Math.abs(dx), Math.abs(dy));
        setModule(cx + dx, cy + dy, v !== 2);
      }
    for (let i = -4; i <= 4; i++) {
      setModule(cx + i, cy - 4, 0); setModule(cx + i, cy + 4, 0);
      setModule(cx - 4, cy + i, 0); setModule(cx + 4, cy + i, 0);
    }
  }

  finderPattern(3, 3);
  finderPattern(size - 4, 3);
  finderPattern(3, size - 4);

  for (let i = 8; i < size - 8; i++) {
    setModule(i, 6, i % 2 === 0);
    setModule(6, i, i % 2 === 0);
  }

  if (ver.v >= 2) {
    const positions = getAlignmentPositions(ver.v);
    for (const ay of positions)
      for (const ax of positions) {
        if (reserved[ay]?.[ax]) continue;
        for (let dy = -2; dy <= 2; dy++)
          for (let dx = -2; dx <= 2; dx++)
            setModule(ax + dx, ay + dy,
              Math.abs(dx) === 2 || Math.abs(dy) === 2 || (dx === 0 && dy === 0));
      }
  }

  setModule(8, size - 8, 1);

  for (let i = 0; i < 8; i++) {
    setModule(i, 8, 0); setModule(8, i, 0);
    setModule(size - 1 - i, 8, 0); setModule(8, size - 1 - i, 0);
  }
  setModule(8, 8, 0);
  reserved[8].fill(1, 0, 9);
  for (let i = 0; i < 9; i++) reserved[i][8] = 1;
  for (let i = 0; i < 8; i++) { reserved[8][size - 8 + i] = 1; reserved[size - 8 + i][8] = 1; }

  if (ver.v >= 7) {
    const vInfo = getVersionInfo(ver.v);
    for (let i = 0; i < 18; i++) {
      const bit = (vInfo >> i) & 1;
      const r = Math.floor(i / 3), c = i % 3;
      setModule(size - 11 + c, r, bit);
      setModule(r, size - 11 + c, bit);
    }
  }

  const ecParams = getECParams(ver.v);
  const dataBits = encodeData(data, ver.v, ecParams);
  placeData(grid, reserved, size, dataBits);
  const bestMask = applyBestMask(grid, reserved, size);
  applyFormatInfo(grid, size, bestMask);
  return grid;
}

function getAlignmentPositions(v) {
  if (v === 1) return [];
  const table = [
    [],[], [6,18],[6,22],[6,26],[6,30],[6,34],
    [6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],
    [6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],
  ];
  return v < table.length ? table[v] : table[table.length - 1];
}

function getVersionInfo(v) {
  const table = [
    0,0,0,0,0,0,0,
    0x07C94,0x085BC,0x09A99,0x0A4D3,0x0BBF6,0x0C762,0x0D847,0x0E60D,0x0F928,
    0x10B78,0x1145D,0x12A17,0x13532,0x149A6,
  ];
  return table[v] || 0;
}

function getECParams(v) {
  const totalCodewords = [0,26,44,70,100,134,172,196,242,292,346,404,466,532,581,655,733,815,901,991,1085];
  const ecCodewordsPerBlock = [0,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28];
  const numBlocks = [0,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,6,6];

  const total = totalCodewords[v] || totalCodewords[20];
  const ecPerBlock = ecCodewordsPerBlock[v] || ecCodewordsPerBlock[20];
  const blocks = numBlocks[v] || numBlocks[20];
  const ecTotal = ecPerBlock * blocks;
  const dataTotal = total - ecTotal;
  const shortBlockData = Math.floor(dataTotal / blocks);
  const longBlocks = dataTotal % blocks;

  return { total, ecPerBlock, blocks, dataTotal, shortBlockData, longBlocks };
}

function encodeData(data, version, ec) {
  const bits = [];
  function pushBits(val, len) {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  }
  pushBits(4, 4);
  const countLen = version <= 9 ? 8 : 16;
  pushBits(data.length, countLen);
  for (const b of data) pushBits(b, 8);
  pushBits(0, Math.min(4, ec.dataTotal * 8 - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const pads = [0xEC, 0x11];
  let pi = 0;
  while (bits.length < ec.dataTotal * 8) {
    pushBits(pads[pi], 8);
    pi ^= 1;
  }

  const dataBytes = [];
  for (let i = 0; i < bits.length; i += 8)
    dataBytes.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));

  const blocks = [];
  let offset = 0;
  for (let b = 0; b < ec.blocks; b++) {
    const len = ec.shortBlockData + (b >= ec.blocks - ec.longBlocks ? 1 : 0);
    blocks.push(dataBytes.slice(offset, offset + len));
    offset += len;
  }

  const ecBlocks = blocks.map(block => rsEncode(block, ec.ecPerBlock));

  const result = [];
  const maxDataLen = ec.shortBlockData + (ec.longBlocks > 0 ? 1 : 0);
  for (let i = 0; i < maxDataLen; i++)
    for (const block of blocks)
      if (i < block.length) result.push(block[i]);
  for (let i = 0; i < ec.ecPerBlock; i++)
    for (const ecb of ecBlocks)
      if (i < ecb.length) result.push(ecb[i]);

  const finalBits = [];
  for (const byte of result)
    for (let i = 7; i >= 0; i--) finalBits.push((byte >> i) & 1);
  return finalBits;
}

/* ── Reed-Solomon（GF(256)）── */
const gfExp = new Uint8Array(512);
const gfLog = new Uint8Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    gfExp[i] = x;
    gfLog[x] = i;
    x = (x << 1) ^ (x >= 128 ? 0x11d : 0);
  }
  for (let i = 255; i < 512; i++) gfExp[i] = gfExp[i - 255];
})();

function gfMul(a, b) {
  return (a === 0 || b === 0) ? 0 : gfExp[gfLog[a] + gfLog[b]];
}

function rsEncode(data, ecLen) {
  const gen = [1];
  for (let i = 0; i < ecLen; i++) {
    const newGen = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      newGen[j] ^= gen[j];
      newGen[j + 1] ^= gfMul(gen[j], gfExp[i]);
    }
    gen.length = 0;
    gen.push(...newGen);
  }

  const msg = new Uint8Array(data.length + ecLen);
  msg.set(data);
  for (let i = 0; i < data.length; i++) {
    const coeff = msg[i];
    if (coeff !== 0)
      for (let j = 0; j < gen.length; j++)
        msg[i + j] ^= gfMul(gen[j], coeff);
  }
  return Array.from(msg.slice(data.length));
}

function placeData(grid, reserved, size, bits) {
  let idx = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) >> 1) & 1;
        const y = upward ? size - 1 - vert : vert;
        if (x < 0 || x >= size || y < 0 || y >= size) continue;
        if (reserved[y][x]) continue;
        grid[y][x] = idx < bits.length ? bits[idx] : 0;
        idx++;
      }
    }
  }
}

function applyBestMask(grid, reserved, size) {
  let bestScore = Infinity, bestMask = 0;
  for (let m = 0; m < 8; m++) {
    const copy = grid.map(r => new Uint8Array(r));
    applyMask(copy, reserved, size, m);
    const score = scoreMask(copy, size);
    if (score < bestScore) { bestScore = score; bestMask = m; }
  }
  applyMask(grid, reserved, size, bestMask);
  return bestMask;
}

function applyMask(grid, reserved, size, mask) {
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      if (reserved[y][x]) continue;
      let flip = false;
      switch (mask) {
        case 0: flip = (y + x) % 2 === 0; break;
        case 1: flip = y % 2 === 0; break;
        case 2: flip = x % 3 === 0; break;
        case 3: flip = (y + x) % 3 === 0; break;
        case 4: flip = (Math.floor(y/2) + Math.floor(x/3)) % 2 === 0; break;
        case 5: flip = (y*x)%2 + (y*x)%3 === 0; break;
        case 6: flip = ((y*x)%2 + (y*x)%3) % 2 === 0; break;
        case 7: flip = ((y+x)%2 + (y*x)%3) % 2 === 0; break;
      }
      if (flip) grid[y][x] ^= 1;
    }
}

function scoreMask(grid, size) {
  let penalty = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size - 4; x++) {
      const v = grid[y][x];
      if (grid[y][x+1]===v && grid[y][x+2]===v && grid[y][x+3]===v && grid[y][x+4]===v)
        penalty += 3;
    }
  }
  for (let x = 0; x < size; x++) {
    for (let y = 0; y < size - 4; y++) {
      const v = grid[y][x];
      if (grid[y+1][x]===v && grid[y+2][x]===v && grid[y+3][x]===v && grid[y+4][x]===v)
        penalty += 3;
    }
  }
  return penalty;
}

function applyFormatInfo(grid, size, mask) {
  const formatBits = getFormatBits(1, mask);
  const positions = [
    [0,8],[1,8],[2,8],[3,8],[4,8],[5,8],[7,8],[8,8],[8,7],[8,5],[8,4],[8,3],[8,2],[8,1],[8,0],
  ];
  positions.forEach(([x, y], i) => { grid[y][x] = (formatBits >> (14 - i)) & 1; });
  const posRight = [];
  for (let i = 0; i < 8; i++) posRight.push([size - 1 - i, 8]);
  for (let i = 0; i < 7; i++) posRight.push([8, size - 7 + i]);
  posRight.forEach(([x, y], i) => { grid[y][x] = (formatBits >> (14 - i)) & 1; });
}

function getFormatBits(ecLevel, mask) {
  const data = (ecLevel << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) ? 0x537 : 0);
  return ((data << 10) | rem) ^ 0x5412;
}

/* ─── QR Scan（jsQR）─── */
let scanStream = null;

async function startScan() {
  if (typeof jsQR === "undefined") { alert("jsQR 函式庫尚未載入。"); return; }
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch { alert("無法存取攝像頭。請確認已授權或使用 HTTPS。"); return; }
  qrVideo.style.display = "block";
  qrVideo.srcObject = scanStream;
  qrVideo.play();
  qrScanBtn.style.display = "none";
  qrStopBtn.style.display = "";
  requestAnimationFrame(scanFrame);
}

function scanFrame() {
  if (!scanStream) return;
  if (qrVideo.readyState >= qrVideo.HAVE_ENOUGH_DATA) {
    const canvas = document.createElement("canvas");
    canvas.width = qrVideo.videoWidth;
    canvas.height = qrVideo.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(qrVideo, 0, 0);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imgData.data, canvas.width, canvas.height);
    if (code?.data) {
      const parsed = parseOtpauthUri(code.data);
      if (parsed) {
        applyParsed(parsed);
        statusEl.textContent = `已掃描：${parsed.name}`;
        statusEl.className = "status ok";
        stopScan();
        return;
      }
    }
  }
  requestAnimationFrame(scanFrame);
}

function stopScan() {
  if (scanStream) {
    scanStream.getTracks().forEach(t => { t.stop(); });
    scanStream = null;
  }
  qrVideo.style.display = "none";
  qrVideo.srcObject = null;
  qrScanBtn.style.display = "";
  qrStopBtn.style.display = "none";
}

/* ─── Copy ─── */
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

/* ─── Events ─── */
verifyBtn.addEventListener("click", verifyCode);
codeInput.addEventListener("keydown", e => { if (e.key === "Enter") verifyCode(); });
[secretInput, digitsSel, periodSel, algorithmSel].forEach(el =>
  el.addEventListener("input", updateDisplay));
skewSel.addEventListener("change", () => {
  statusEl.textContent = "等待輸入";
  statusEl.className = "status bad";
});
qrGenBtn.addEventListener("click", generateQR);
qrScanBtn.addEventListener("click", startScan);
qrStopBtn.addEventListener("click", stopScan);

/* ─── URL path secret ─── */
(function applySecretFromPath() {
  const path = decodeURIComponent(window.location.pathname || "");
  const parts = path.split("/").filter(Boolean);
  const last = parts[parts.length - 1];
  if (!last) return;
  secretInput.value = last.toLowerCase().startsWith("key=") ? last.slice(4) : last;
})();

/* ─── Init ─── */
renderHistory();
setInterval(updateDisplay, 1000);
updateDisplay();

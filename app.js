const $ = (id) => document.getElementById(id);

const state = {
  manifest: null,   // raw encrypted bundle (decrypted-manifest fields live below)
  key: null,        // imported CryptoKey
  files: null,      // path -> { id, mime, size }   (decrypted manifest)
  paths: [],        // sorted list of all paths
  cache: new Map(), // path -> { bytes: Uint8Array, mime, url? }
  chromeInjected: false,
};

/* ---------- IndexedDB (persistent key storage) ----------
   We store the AES-GCM CryptoKey as a non-extractable object.
   IndexedDB supports structured clone of CryptoKey objects, so the raw key
   bytes never need to leave the SubtleCrypto sandbox. Even malicious script
   in the same origin cannot exfiltrate the raw key — only USE it on this site. */
const IDB_NAME = "vault-store";
const IDB_STORE = "keys";

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbDo(mode, fn) {
  return idbOpen().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, mode);
    const store = tx.objectStore(IDB_STORE);
    const req = fn(store);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }));
}
const idbGet = (k)    => idbDo("readonly",  s => s.get(k));
const idbSet = (k, v) => idbDo("readwrite", s => s.put(v, k));
const idbDel = (k)    => idbDo("readwrite", s => s.delete(k));

/* ---------- helpers ---------- */
const b64dec = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const escapeHtml = (s) =>
  s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );

const stripExt = (name) => name.replace(/\.md$/i, "");

const iconForFile = (name) => {
  if (/\.md$/i.test(name)) return "📄";
  if (/\.(png|jpg|jpeg|gif|svg|webp)$/i.test(name)) return "🖼";
  if (/\.pdf$/i.test(name)) return "📕";
  if (/\.(mp3|wav|ogg|m4a)$/i.test(name)) return "🎵";
  if (/\.(mp4|webm|mov)$/i.test(name)) return "🎬";
  return "📎";
};

/* ---------- progress bar ---------- */
const progress = {
  current: 0,
  show() {
    const el = $("lock-progress");
    el.classList.add("visible");
    el.classList.remove("done");
    this.current = 0;
    this.set(0, "Preparing…");
  },
  hide() {
    const el = $("lock-progress");
    el.classList.remove("visible");
    el.classList.remove("done");
    $("lock-progress-fill").style.width = "0%";
    this.current = 0;
  },
  /** Snap fill to a pct + update label. Use for milestones. */
  async set(pct, label) {
    pct = Math.max(this.current, Math.min(100, pct));
    this.current = pct;
    if (label) $("lock-progress-text").textContent = label;
    $("lock-progress-pct").textContent = Math.round(pct) + "%";
    $("lock-progress-fill").style.width = pct + "%";
    $("lock-progress").setAttribute("aria-valuenow", String(Math.round(pct)));
    // small yield so the browser paints between awaited steps
    await sleep(20);
  },
  /** "Creep" the bar toward `target` over `durationMs`, then resolve.
   *  Cancellable by calling set() with a higher value, which races ahead. */
  creepTo(target, durationMs) {
    const start = performance.now();
    const from = this.current;
    return new Promise((resolve) => {
      const step = (now) => {
        if (this.current >= target) return resolve();
        const t = Math.min(1, (now - start) / durationMs);
        // ease-out
        const eased = 1 - Math.pow(1 - t, 3);
        const next = from + (target - from) * eased;
        if (next > this.current) {
          this.current = next;
          $("lock-progress-fill").style.width = next + "%";
          $("lock-progress-pct").textContent = Math.round(next) + "%";
          $("lock-progress").setAttribute("aria-valuenow", String(Math.round(next)));
        }
        if (t < 1) requestAnimationFrame(step);
        else resolve();
      };
      requestAnimationFrame(step);
    });
  },
  finish() {
    $("lock-progress").classList.add("done");
  },
};

/* ---------- crypto ---------- */
async function deriveKey(password) {
  const { salt, iter } = state.manifest;
  if (!salt || !iter) throw new Error("missing parameters");
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: b64dec(salt), iterations: iter, hash: "SHA-512" },
    baseKey,
    256
  );
  return crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["decrypt"]);
}

async function decryptBlob(b64, key) {
  const buf = b64dec(b64);
  const iv = buf.slice(0, 12);
  const ctTag = buf.slice(12); // WebCrypto wants ciphertext||tag together
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ctTag);
  return new Uint8Array(pt);
}

/* ---------- bundle ---------- */
async function loadManifest() {
  const res = await fetch("content.enc.json", { cache: "no-store" });
  if (!res.ok) throw new Error("network error");
  state.manifest = await res.json();
  if (state.manifest.v !== 3 || !state.manifest.blobs || !state.manifest.manifest) {
    throw new Error("Unsupported bundle version. Rebuild with the current vault.py.");
  }
}

/** Try to derive a key + verify against the check token. */
async function verifyKey(key) {
  try {
    const pt = await decryptBlob(state.manifest.check, key);
    return new TextDecoder().decode(pt) === "OBSIDIAN_VAULT_v1";
  } catch {
    return false;
  }
}

/** Decrypt the encrypted file manifest and inject the encrypted chrome CSS.
 *  Idempotent — safe to call from both fresh unlock and session restore. */
async function loadDecryptedChromeAndManifest() {
  const manifestPt = await decryptBlob(state.manifest.manifest, state.key);
  state.files = JSON.parse(new TextDecoder().decode(manifestPt));
  state.paths = Object.keys(state.files).sort();

  if (!state.chromeInjected) {
    const chromePt = await decryptBlob(state.manifest.chrome, state.key);
    const css = new TextDecoder().decode(chromePt);
    const style = document.createElement("style");
    style.id = "chrome-style";
    style.textContent = css;
    document.head.appendChild(style);
    state.chromeInjected = true;
  }
}

async function decryptFile(path) {
  if (state.cache.has(path)) return state.cache.get(path);
  const meta = state.files[path];
  if (!meta) return null;
  const ct = state.manifest.blobs[meta.id];
  if (!ct) return null;
  const bytes = await decryptBlob(ct, state.key);
  const obj = { bytes, mime: meta.mime };
  state.cache.set(path, obj);
  return obj;
}

async function getBlobUrl(path) {
  const f = await decryptFile(path);
  if (!f) return null;
  if (!f.url) f.url = URL.createObjectURL(new Blob([f.bytes], { type: f.mime }));
  return f.url;
}

/* ---------- tree ---------- */
function buildTree() {
  const root = { dirs: new Map(), files: [] };
  for (const path of state.paths) {
    const parts = path.split("/");
    let cur = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i];
      if (!cur.dirs.has(seg)) cur.dirs.set(seg, { dirs: new Map(), files: [] });
      cur = cur.dirs.get(seg);
    }
    cur.files.push({ name: parts[parts.length - 1], path });
  }
  return root;
}

function renderTree(node, container, depth = 0) {
  // directories first
  for (const [name, child] of node.dirs) {
    const dir = document.createElement("div");
    dir.className = "tree-dir";
    const row = document.createElement("div");
    row.className = "tree-row tree-dir-row";
    row.style.paddingLeft = depth * 12 + 8 + "px";
    row.innerHTML = `
      <span class="tree-caret">▾</span>
      <span class="tree-label">${escapeHtml(name)}</span>
    `;
    const children = document.createElement("div");
    children.className = "tree-children";
    row.addEventListener("click", () => dir.classList.toggle("collapsed"));
    dir.appendChild(row);
    dir.appendChild(children);
    container.appendChild(dir);
    renderTree(child, children, depth + 1);
  }
  // then files
  for (const file of node.files) {
    const row = document.createElement("div");
    row.className = "tree-row tree-file-row";
    row.style.paddingLeft = depth * 12 + 24 + "px";
    row.dataset.path = file.path;
    row.innerHTML = `
      <span class="tree-icon">${iconForFile(file.name)}</span>
      <span class="tree-label">${escapeHtml(stripExt(file.name))}</span>
    `;
    row.addEventListener("click", () => openFile(file.path));
    container.appendChild(row);
  }
}

/* ---------- wikilinks ---------- */
function resolveWikiPath(target) {
  if (state.files[target]) return target;
  const exts = [".md", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf"];
  for (const ext of exts) if (state.files[target + ext]) return target + ext;
  // basename match
  for (const p of state.paths) {
    const base = p.split("/").pop();
    if (base === target) return p;
    for (const ext of exts) if (base === target + ext) return p;
  }
  // basename without extension
  const lower = target.toLowerCase();
  for (const p of state.paths) {
    const base = stripExt(p.split("/").pop()).toLowerCase();
    if (base === lower) return p;
  }
  return null;
}

async function preprocessMarkdown(text) {
  // ![[file]]  -> decrypt and inline as image / link
  const embeds = [...text.matchAll(/!\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g)];
  for (const m of embeds) {
    const target = m[1].trim();
    const resolved = resolveWikiPath(target);
    if (!resolved) {
      text = text.replace(
        m[0],
        `<span class="wikilink missing">${escapeHtml(target)}</span>`
      );
      continue;
    }
    const meta = state.files[resolved];
    if (meta.mime.startsWith("image/")) {
      const url = await getBlobUrl(resolved);
      text = text.replace(m[0], `![${escapeHtml(target)}](${url})`);
    } else {
      text = text.replace(
        m[0],
        `<a href="#" class="wikilink" data-wiki="${escapeHtml(resolved)}">${escapeHtml(target)}</a>`
      );
    }
  }

  // [[link|label]]  -> internal link
  text = text.replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (_full, target, label) => {
    const t = target.trim();
    const resolved = resolveWikiPath(t);
    const display = escapeHtml((label || t).trim());
    if (!resolved) return `<span class="wikilink missing">${display}</span>`;
    return `<a href="#" class="wikilink" data-wiki="${escapeHtml(resolved)}">${display}</a>`;
  });

  return text;
}

/* ---------- viewing ---------- */
function setActive(path) {
  document.querySelectorAll(".tree-file-row.active").forEach((el) => el.classList.remove("active"));
  const sel = document.querySelector(`.tree-file-row[data-path="${CSS.escape(path)}"]`);
  if (sel) {
    sel.classList.add("active");
    // expand ancestors
    let p = sel.parentElement;
    while (p) {
      if (p.classList && p.classList.contains("tree-dir")) p.classList.remove("collapsed");
      p = p.parentElement;
    }
    sel.scrollIntoView({ block: "nearest" });
  }
}

function renderBreadcrumb(path) {
  const parts = path.split("/");
  $("breadcrumb").innerHTML = parts
    .map((p, i) => `<span class="bc-part">${escapeHtml(i === parts.length - 1 ? stripExt(p) : p)}</span>`)
    .join('<span class="bc-sep">/</span>');
}

const isMobile = () => window.matchMedia("(max-width: 820px)").matches;
function closeMobileSidebar() {
  $("app").classList.remove("menu-open");
}
function toggleMobileSidebar() {
  $("app").classList.toggle("menu-open");
}

async function openFile(path) {
  setActive(path);
  renderBreadcrumb(path);
  if (isMobile()) closeMobileSidebar();

  const file = await decryptFile(path);
  if (!file) return;
  const ext = path.split(".").pop().toLowerCase();
  const article = $("article");

  if (ext === "md" || file.mime === "text/markdown") {
    const raw = new TextDecoder().decode(file.bytes);
    const processed = await preprocessMarkdown(raw);
    const html = marked.parse(processed, { gfm: true, breaks: true });
    article.innerHTML = `<div class="markdown-body">${html}</div>`;

    article.querySelectorAll("pre code").forEach((b) => {
      try { hljs.highlightElement(b); } catch {}
    });
    article.querySelectorAll("[data-wiki]").forEach((a) => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        openFile(a.dataset.wiki);
      });
    });
  } else if (file.mime.startsWith("image/")) {
    const url = await getBlobUrl(path);
    article.innerHTML = `<div class="image-view"><img src="${url}" alt="${escapeHtml(path)}"></div>`;
  } else if (ext === "pdf") {
    const url = await getBlobUrl(path);
    article.innerHTML = `<div class="pdf-view-wrap"><embed src="${url}" type="application/pdf" class="pdf-view"></div>`;
  } else if (file.mime.startsWith("audio/")) {
    const url = await getBlobUrl(path);
    article.innerHTML = `<audio controls src="${url}" style="width:100%"></audio>`;
  } else if (file.mime.startsWith("video/")) {
    const url = await getBlobUrl(path);
    article.innerHTML = `<video controls src="${url}" style="width:100%;border-radius:10px"></video>`;
  } else if (file.mime.startsWith("text/")) {
    const text = new TextDecoder().decode(file.bytes);
    article.innerHTML = `<pre class="raw-view" style="text-align:left">${escapeHtml(text)}</pre>`;
  } else {
    article.innerHTML = `<div class="raw-view">No inline preview for <code>${escapeHtml(path.split("/").pop())}</code>.</div>`;
  }

  window.scrollTo({ top: 0 });
  history.replaceState(null, "", "#" + encodeURIComponent(path));
}

/* ---------- search filter ---------- */
function applySearch(q) {
  q = q.trim().toLowerCase();
  const rows = document.querySelectorAll(".tree-row");
  if (!q) {
    rows.forEach((r) => (r.style.display = ""));
    document.querySelectorAll(".tree-dir").forEach((d) => d.classList.remove("force-open"));
    return;
  }
  // file matching
  const visibleDirs = new Set();
  document.querySelectorAll(".tree-file-row").forEach((row) => {
    const p = row.dataset.path.toLowerCase();
    if (p.includes(q)) {
      row.style.display = "";
      let parent = row.parentElement;
      while (parent && parent.classList) {
        if (parent.classList.contains("tree-dir")) visibleDirs.add(parent);
        parent = parent.parentElement;
      }
    } else {
      row.style.display = "none";
    }
  });
  document.querySelectorAll(".tree-dir").forEach((d) => {
    if (visibleDirs.has(d)) {
      d.style.display = "";
      d.classList.remove("collapsed");
    } else {
      d.style.display = "none";
    }
  });
}

/* ---------- session persistence ---------- */
const SESSION_KEY = "current";

async function trySavedUnlock() {
  let saved;
  try { saved = await idbGet(SESSION_KEY); } catch { return false; }
  if (!saved || !saved.key || saved.salt !== state.manifest.salt) {
    if (saved && saved.salt !== state.manifest.salt) {
      // bundle was rebuilt with a new salt — the stored key is dead. clear it.
      try { await idbDel(SESSION_KEY); } catch {}
    }
    return false;
  }
  if (!(await verifyKey(saved.key))) {
    try { await idbDel(SESSION_KEY); } catch {}
    return false;
  }
  state.key = saved.key;
  return true;
}

async function saveSession() {
  try {
    await idbSet(SESSION_KEY, { key: state.key, salt: state.manifest.salt });
  } catch (e) {
    console.warn("Could not persist session key:", e);
  }
}
async function clearSession() {
  try { await idbDel(SESSION_KEY); } catch {}
}

function enterApp() {
  $("lock-screen").classList.add("hidden");
  $("app").classList.remove("hidden");
  const root = buildTree();
  $("tree").innerHTML = "";
  renderTree(root, $("tree"));
  $("sidebar-stats").textContent = `${state.paths.length} files · v${state.manifest.v}`;
  if (location.hash) {
    const p = decodeURIComponent(location.hash.slice(1));
    if (state.files[p]) openFile(p);
  }
}

/* ---------- unlock orchestration ---------- */
/** Drive the progress bar from "key ready" through manifest + chrome + handoff. */
async function finalizeUnlock() {
  await progress.set(55, "Decrypting manifest…");
  await loadDecryptedChromeAndManifest();
  await progress.set(85, "Loading interface…");
  // tiny pause lets the gradient finish its glide before we hand off
  await sleep(120);
  await progress.set(100, "Ready");
  progress.finish();
  await sleep(220);
  enterApp();
}

async function unlockWithPassword(password) {
  $("lock-error").textContent = "";
  progress.show();

  // Stage 1 — derive the key. PBKDF2 inside SubtleCrypto is opaque, so we
  // creep the bar toward 45% over ~1.6s; if derivation finishes earlier we
  // snap forward, if it takes longer the bar simply pauses there.
  await progress.set(5, "Deriving key…");
  progress.creepTo(45, 1600);

  let key;
  try {
    key = await deriveKey(password);
  } catch (e) {
    console.warn("deriveKey failed", e);
    progress.hide();
    return false;
  }

  // Stage 2 — verify against the check token.
  await progress.set(50, "Verifying…");
  if (!(await verifyKey(key))) {
    progress.hide();
    return false;
  }

  state.key = key;
  await finalizeUnlock();
  return true;
}

async function unlockFromSavedKey() {
  progress.show();
  await progress.set(35, "Restoring session…");
  // creep gives the silent path a little breathing room visually
  await progress.creepTo(50, 350);
  await finalizeUnlock();
}

/* ---------- init ---------- */
async function init() {
  try {
    await loadManifest();
  } catch (e) {
    console.error(e);
    $("lock-error").textContent = "Something went wrong loading the bundle.";
    return;
  }

  wireListeners();

  // try silent unlock from persistent storage
  if (await trySavedUnlock()) {
    await unlockFromSavedKey();
    return;
  }
}

function wireListeners() {
  $("unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("unlock-btn");
    const pw = $("password").value;
    if (!pw) return;
    btn.disabled = true;
    btn.classList.add("loading");
    // small yield so the spinner can paint
    await sleep(20);
    const ok = await unlockWithPassword(pw);
    btn.classList.remove("loading");
    btn.disabled = false;
    if (!ok) {
      $("lock-error").textContent = "Incorrect password.";
      $("password").select();
      return;
    }
    if ($("remember").checked) await saveSession();
    else await clearSession();
  });

  $("search-btn").addEventListener("click", () => {
    $("sidebar-search").classList.toggle("hidden");
    if (!$("sidebar-search").classList.contains("hidden")) $("search-input").focus();
  });

  $("mobile-toggle").addEventListener("click", toggleMobileSidebar);
  $("sidebar-backdrop").addEventListener("click", closeMobileSidebar);

  $("collapse-btn").addEventListener("click", () => {
    document.querySelectorAll(".tree-dir").forEach((d) => d.classList.add("collapsed"));
  });

  $("search-input").addEventListener("input", (e) => applySearch(e.target.value));

  $("lock-btn").addEventListener("click", async () => {
    state.key = null;
    state.cache.forEach((v) => v.url && URL.revokeObjectURL(v.url));
    state.cache.clear();
    await clearSession();
    location.reload();
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      $("sidebar-search").classList.remove("hidden");
      $("search-input").focus();
      $("search-input").select();
    }
    if (e.key === "Escape" && document.activeElement === $("search-input")) {
      $("search-input").value = "";
      applySearch("");
      $("sidebar-search").classList.add("hidden");
    }
    if (e.key === "Escape" && $("app").classList.contains("menu-open")) {
      closeMobileSidebar();
    }
  });
}

init();

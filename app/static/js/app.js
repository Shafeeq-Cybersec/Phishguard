/* PhishGuard AI — scanner UI logic. Pure consumer of the JSON API. */

const el = (id) => document.getElementById(id);
const urlInput = el("urlInput");
const scanBtn  = el("scanBtn");

/* ---------- inline model meta ---------- */
async function loadStats() {
  try {
    const d = await (await fetch("/api/stats")).json();
    const m = d.metrics || {};
    setStat("accuracy", m.accuracy == null ? "…" : (m.accuracy * 100).toFixed(1) + "%");
    setStat("roc_auc",  m.roc_auc == null ? "…" : Math.round(m.roc_auc * 100) + "%");
    setStat("trained_on", d.trained_on ? compact(d.trained_on) : "…");
  } catch { /* leave placeholders */ }
}
function setStat(name, value) {
  const n = document.querySelector(`[data-stat="${name}"]`);
  if (n) n.textContent = value;
}
const compact = (n) => (n >= 1000 ? Math.round(n / 1000) + "K" : String(n));

/* ---------- staged processing animation ---------- */
const STEPS = ["Extracting features", "Running Random Forest", "Calculating risk"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runProcessing() {
  const box = el("processing");
  box.innerHTML = "";
  box.hidden = false;
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });

  for (const label of STEPS) {
    const row = document.createElement("div");
    row.className = "proc-step";
    row.innerHTML = `<span class="proc-label"></span>
      <div class="proc-bar"><div class="proc-fill"></div></div>`;
    row.querySelector(".proc-label").textContent = label;
    box.appendChild(row);
    await sleep(60);                                   // let it mount
    row.querySelector(".proc-fill").style.width = "100%"; // animate the bar
    await sleep(560);                                  // bar fill duration
    row.classList.add("done");
  }
  const done = document.createElement("div");
  done.className = "proc-done";
  done.textContent = "Done";
  box.appendChild(done);
  await sleep(380);
}

/* ---------- scanning ---------- */
async function doScan(url) {
  const r = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "Scan failed.");
  return data;
}

async function scan() {
  const url = urlInput.value.trim();
  hideError();
  if (!url) { showError("Please enter a URL to scan."); return; }

  el("resultCard").hidden = true;
  setLoading(true);
  try {
    // Run the animation and the real request together; the animation gives a
    // guaranteed minimum display time so all stages are always seen.
    const [data] = await Promise.all([doScan(url), runProcessing()]);
    el("processing").hidden = true;
    renderResult(data);
  } catch (e) {
    el("processing").hidden = true;
    showError(e.message || "Could not reach the scanning engine. Is the server running?");
  } finally {
    setLoading(false);
  }
}

const ICONS = {
  safe: '<svg viewBox="0 0 24 24" fill="none"><path d="M20 6 9 17l-5-5" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  suspicious: '<svg viewBox="0 0 24 24" fill="none"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 9v4m0 4h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  phishing: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 2 4 5v6c0 5 3.4 8.6 8 11 4.6-2.4 8-6 8-11V5l-8-3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 8v4m0 4h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
};
const SUBS = {
  safe: "This link looks legitimate.",
  suspicious: "Treat this link with caution.",
  phishing: "This link is likely phishing.",
};

function renderResult(d) {
  const card = el("resultCard");
  const verdict = d.verdict.toLowerCase(); // safe | suspicious | phishing
  card.className = "result " + verdict;     // sets --vc; colors flow from CSS
  card.hidden = false;

  el("verdictIcon").innerHTML = ICONS[verdict] || "";
  el("verdictBadge").textContent = d.verdict;
  el("verdictSub").textContent = SUBS[verdict] || "";

  el("riskBar").style.width = d.risk_score + "%";
  animateNumber(el("gaugeScore"), d.risk_score);

  el("detailUrl").textContent = d.normalized || d.url;

  // Domain analysis: show Organization for legit brands, "Claimed Brand" for spoofs
  const dom = d.domain || {};
  el("regDomain").textContent = dom.registered_domain || "—";

  const orgRow = el("orgRow");
  const claimedRow = el("claimedRow");
  if (dom.claimed_brand && !dom.impersonation) {
    // Legitimate brand domain (e.g. paypal.com, google.com)
    orgRow.hidden = false;
    el("orgName").textContent = dom.claimed_brand;
    claimedRow.hidden = true;
  } else if (dom.claimed_brand && dom.impersonation) {
    // Spoof: brand is claimed but it's fake
    orgRow.hidden = true;
    claimedRow.hidden = false;
    el("claimedBrand").textContent = dom.claimed_brand;
  } else {
    orgRow.hidden = true;
    claimedRow.hidden = true;
  }

  el("impersonationPill").hidden = !dom.impersonation;

  // Trusted pill: show final adjusted risk, not raw model score
  const trustedPill = el("trustedRow");
  trustedPill.hidden = !d.trusted;
  if (d.trusted) el("adjustedRisk").textContent = d.risk_score + "%";

  // HTTPS note (only shown when the URL uses https)
  el("httpsBlock").hidden = !d.https;

  renderBreakdown(d.risk_breakdown);
  renderKeywords(d.keywords);
  renderFeatures(d.features);

  // Long-URL explanation appears only when the URL is actually long
  const lengthFeat = (d.features || []).find((f) => f.label === "Length");
  el("lenNote").hidden = !(lengthFeat && lengthFeat.value >= 75);

  // Random Forest tree votes (real ensemble breakdown)
  const tv = d.tree_votes || {};
  el("votePhish").textContent = tv.phishing_trees ?? "—";
  el("voteSafe").textContent = tv.safe_trees ?? "—";
  el("voteFinal").textContent = (tv.vote_pct ?? 0) + "% phishing";
  el("voteConf").textContent = (d.model_risk ?? 0) + "%";
  // Only explain an override when the model actually disagreed with the allowlist.
  const vn = el("voteNote");
  const overridden = d.trusted && d.model_risk >= 50;
  vn.hidden = !overridden;
  if (overridden) {
    vn.innerHTML = "The model leans phishing, but this domain is on our trusted " +
      "allowlist, so the final verdict is overridden to <b>safe</b>.";
  }

  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderBreakdown(bd) {
  const list = el("breakdownList");
  list.innerHTML = "";
  const items = (bd && bd.items) || [];
  if (!items.length) {
    list.innerHTML = '<li class="kw-empty">No notable risk factors.</li>';
  } else {
    items.forEach((it) => {
      const li = document.createElement("li");
      li.className = "bd-item";
      li.innerHTML = '<span class="bd-label"></span><span class="bd-pct"></span>' +
        '<div class="bd-bar"><div class="bd-fill"></div></div>';
      li.querySelector(".bd-label").textContent = it.label;
      li.querySelector(".bd-pct").textContent = "+" + it.pct + "%";
      list.appendChild(li);
      requestAnimationFrame(() => {
        li.querySelector(".bd-fill").style.width = Math.min(it.pct, 100) + "%";
      });
    });
  }
  el("breakdownTotal").textContent = ((bd && bd.total) || 0) + "%";
}

function renderKeywords(kw) {
  const box = el("keywordsList");
  box.innerHTML = "";
  if (!kw || !kw.length) {
    box.innerHTML = '<span class="kw-empty">None detected.</span>';
    return;
  }
  kw.forEach((w) => {
    const s = document.createElement("span");
    s.className = "kw";
    s.textContent = w;
    box.appendChild(s);
  });
}

function renderFeatures(feats) {
  const box = el("featTable");
  box.innerHTML = "";
  (feats || []).forEach((f) => {
    const c = document.createElement("div");
    c.className = "feat-cell";
    c.innerHTML = "<span></span><b></b>";
    c.querySelector("span").textContent = f.label;
    c.querySelector("b").textContent = f.value;
    box.appendChild(c);
  });
}

function animateNumber(node, target) {
  const start = performance.now(), dur = 800;
  (function tick(now) {
    const t = Math.min((now - start) / dur, 1);
    node.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(tick);
  })(start);
}

/* ---------- ui helpers ---------- */
function setLoading(on) {
  scanBtn.classList.toggle("loading", on);
  scanBtn.disabled = on;
  urlInput.disabled = on;
}
function showError(msg) { const b = el("errorBox"); b.textContent = msg; b.hidden = false; }
function hideError() { el("errorBox").hidden = true; }

/* ---------- events ---------- */
scanBtn.addEventListener("click", scan);
urlInput.addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });
document.querySelectorAll(".chip").forEach((chip) =>
  chip.addEventListener("click", () => { urlInput.value = chip.dataset.url; scan(); })
);

loadStats();

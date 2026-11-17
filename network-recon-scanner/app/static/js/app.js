// Front end logic. All scan data is untrusted (banners come from remote hosts),
// so we only ever write it with textContent, never innerHTML.
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
let pollTimer = null;

async function api(url, opts) {
  const r = await fetch(url, opts);
  const data = r.status === 204 ? null : await r.json();
  if (!r.ok) throw new Error((data && data.error) || "Request failed");
  return data;
}

$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("form-msg");
  msg.className = "msg"; msg.textContent = "";
  $("go").disabled = true;
  try {
    const { id } = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: $("target").value, profile: $("profile").value,
        authorized: $("authorized").checked,
      }),
    });
    watch(id);
  } catch (err) {
    msg.className = "msg err"; msg.textContent = err.message;
    $("go").disabled = false;
  }
});

function watch(id) {
  clearInterval(pollTimer);
  $("result-panel").hidden = false;
  const tick = async () => {
    const scan = await api(`/api/scans/${id}`);
    renderScan(scan);
    if (scan.status === "done" || scan.status === "error") {
      clearInterval(pollTimer); $("go").disabled = false; loadHistory();
    }
  };
  tick(); pollTimer = setInterval(tick, 2000);
}

function renderScan(scan) {
  $("result-title").textContent = `Scan #${scan.id}: ${scan.target} (${scan.profile})`;
  const box = $("result"); box.replaceChildren();
  if (scan.status === "queued" || scan.status === "running") {
    box.append(el("p", "spin", `Status: ${scan.status}. Large ranges can take a few minutes`)); return;
  }
  if (scan.status === "error") { box.append(el("p", "msg err", scan.error)); return; }
  const r = scan.result, s = r.summary;

  const stats = el("div", "stats");
  [["Hosts up", s.hosts_up], ["Open ports", s.open_ports],
   ["High", s.severity.high], ["Medium", s.severity.medium], ["Low", s.severity.low]]
    .forEach(([k, v]) => { const d = el("div"); d.append(el("b", "", v), el("span", "", k)); stats.append(d); });
  box.append(stats);

  const exp = el("p");
  ["json", "csv", "html"].forEach((f) => {
    const a = el("a", "", `Export ${f.toUpperCase()}`);
    a.href = `/api/scans/${scan.id}/export?fmt=${f}`; a.style.marginRight = "1rem"; exp.append(a);
  });
  box.append(exp);

  box.append(el("h3", "", "Findings"));
  if (!r.findings.length) box.append(el("p", "msg", "No findings from the rule set. This is not proof the host is safe."));
  r.findings.forEach((f) => {
    const d = el("div", `finding ${f.severity}`);
    const head = el("div"); head.append(el("span", `sev ${f.severity}`, f.severity),
      el("strong", "", ` ${f.host}${f.port ? ":" + f.port : ""}: ${f.title}`));
    d.append(head, el("small", "", f.detail), el("small", "", `Fix: ${f.recommendation}`));
    box.append(d);
  });

  box.append(el("h3", "", "Hosts and ports"));
  const wrap = el("div", "scroll"), t = el("table");
  const hr = el("tr"); ["Host", "Port", "State", "Service", "Version"].forEach((h) => hr.append(el("th", "", h)));
  t.append(hr);
  r.hosts.forEach((h) => {
    if (!h.ports.length) {
      const row = el("tr"); row.append(el("td", "", h.ip + (h.hostname ? ` (${h.hostname})` : "")),
        el("td", "", "-"), el("td", "", h.status), el("td", "", "-"), el("td", "", h.os || "-")); t.append(row);
    }
    h.ports.forEach((p) => {
      const row = el("tr");
      row.append(el("td", "", h.ip), el("td", "", `${p.port}/${p.protocol}`), el("td", "", p.state),
        el("td", "", p.service), el("td", "", `${p.product} ${p.version}`.trim() || "-"));
      t.append(row);
    });
  });
  wrap.append(t); box.append(wrap);
}

async function loadHistory() {
  const scans = await api("/api/scans");
  const body = document.querySelector("#history tbody"); body.replaceChildren();
  $("empty").hidden = scans.length > 0;
  scans.forEach((s) => {
    const row = el("tr");
    const sev = s.summary ? `${s.summary.severity.high}H / ${s.summary.severity.medium}M / ${s.summary.severity.low}L` : "-";
    [s.id, s.target, s.profile, s.status, s.created_at, sev].forEach((v) => row.append(el("td", "", v)));
    const act = el("td");
    const open = el("button", "link", "Open"); open.onclick = () => { watch(s.id); window.scrollTo(0, 0); };
    const del = el("button", "link", "Delete");
    del.onclick = async () => { await api(`/api/scans/${s.id}`, { method: "DELETE" }); loadHistory(); };
    act.append(open, del); row.append(act); body.append(row);
  });
}
loadHistory();

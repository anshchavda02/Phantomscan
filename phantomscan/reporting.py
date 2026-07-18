"""Report generation for PhantomScan."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


SEVERITIES = ["critical", "high", "medium", "low", "info"]


def write_json_report(path: Path, payload: dict[str, Any]) -> None:
    """Write a JSON report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_csv_report(path: Path, payload: dict[str, Any]) -> None:
    """Write a CSV report of findings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = payload.get("findings", [])
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Title", "Severity", "Confidence", "Category"])
        for item in findings:
            writer.writerow([
                payload.get("target", ""),
                item.get("title", ""),
                item.get("severity", "info"),
                item.get("confidence", ""),
                item.get("category", "")
            ])


def write_html_report(path: Path, payload: dict[str, Any]) -> None:
    """Write a polished self-contained HTML report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    report_json = json.dumps(payload, sort_keys=True)
    escaped_json = report_json.replace("</", "<\\/")
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhantomScan Report - {h(payload.get('target'))}</title>
<style>
:root {{
  --bg:#0a0a0f; --surface:#0f0f1a; --card:#141428; --card-hover:#1a1a35;
  --border:#1e1e3a; --border-glow:#2a2a5a; --accent:#7b5ea7;
  --accent2:#00c9ff; --accent3:#ff6b9d; --text:#e8e8f8;
  --text-muted:#7878a0; --text-dim:#4a4a70; --crit:#ff3355;
  --crit-bg:rgba(255,51,85,0.08); --crit-border:rgba(255,51,85,0.25);
  --high:#ff6b35; --high-bg:rgba(255,107,53,0.08); --high-border:rgba(255,107,53,0.25);
  --med:#ffcc00; --med-bg:rgba(255,204,0,0.08); --med-border:rgba(255,204,0,0.25);
  --low:#00e676; --low-bg:rgba(0,230,118,0.08); --low-border:rgba(0,230,118,0.25);
  --info:#448aff; --info-bg:rgba(68,138,255,0.08); --info-border:rgba(68,138,255,0.25);
}}
:root.light {{
  --bg:#f7f8fc; --surface:#ffffff; --card:#ffffff; --card-hover:#f0f5ff;
  --border:#d9e0ef; --border-glow:#b9c6df; --text:#151728;
  --text-muted:#526078; --text-dim:#7d889b;
  --hero-bg:linear-gradient(135deg,#f7f8fc 0%,#edf0f8 50%,#f7f8fc 100%);
  --intel-bg:linear-gradient(180deg,#ffffff 0%,#f0f5ff 100%);
  --nav-bg:rgba(255,255,255,.9);
  --footer-bg:#e2e8f0;
  --code-bg:#f8fafc;
}}
* {{ box-sizing:border-box; }}
html {{ scroll-behavior:smooth; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.6 Inter, system-ui, -apple-system, Segoe UI, sans-serif; }}
a {{ color:var(--accent2); text-decoration:none; }}
code, pre, .mono {{ font-family:"JetBrains Mono", "Fira Code", Consolas, monospace; }}
.hero {{ position:relative; min-height:420px; overflow:hidden; background:var(--hero-bg, linear-gradient(135deg,#0a0a0f 0%,#0f0a1f 25%,#0a1020 50%,#0f0a1f 75%,#0a0a0f 100%)); border-bottom:1px solid var(--border); }}
.hero:before {{ content:""; position:absolute; inset:-30%; background:radial-gradient(circle at 20% 30%,rgba(0,201,255,.24),transparent 22%),radial-gradient(circle at 80% 20%,rgba(255,107,157,.18),transparent 24%),radial-gradient(circle at 50% 80%,rgba(123,94,167,.26),transparent 24%); animation:mesh 12s ease-in-out infinite alternate; }}
.hero:after {{ content:""; position:absolute; inset:0; background-image:radial-gradient(rgba(255,255,255,.2) 1px, transparent 1px); background-size:42px 42px; opacity:.16; }}
@keyframes mesh {{ from {{ transform:translate3d(-2%,0,0) scale(1); }} to {{ transform:translate3d(2%,3%,0) scale(1.08); }} }}
.hero-inner {{ position:relative; z-index:1; max-width:1240px; margin:0 auto; padding:54px 24px 28px; display:grid; grid-template-columns:1.1fr .9fr; gap:30px; align-items:center; }}
.brand {{ font-size:54px; line-height:1; font-weight:800; letter-spacing:0; }}
.brand span {{ color:var(--accent2); text-shadow:0 0 22px rgba(0,201,255,.35); }}
.tagline {{ color:var(--text-muted); font-size:18px; margin-top:12px; }}
.pill {{ display:inline-flex; align-items:center; gap:6px; border:1px solid var(--border-glow); background:rgba(255,255,255,.04); border-radius:999px; padding:5px 10px; color:var(--text); font-size:12px; }}
.hero-card {{ padding:22px; border:1px solid rgba(255,255,255,.08); border-radius:18px; backdrop-filter:blur(10px); background:rgba(255,255,255,.03); box-shadow:0 20px 80px rgba(0,0,0,.28); }}
.target {{ font-size:28px; font-weight:700; word-break:break-word; }}
.meta-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; margin-top:20px; }}
.meta {{ padding:12px; background:rgba(0,0,0,.18); border:1px solid var(--border); border-radius:12px; }}
.label {{ color:var(--text-muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }}
.value {{ font-weight:700; margin-top:3px; }}
.confidential {{ position:relative; z-index:1; background:rgba(255,51,85,.12); color:#ffd4dc; border-top:1px solid var(--crit-border); border-bottom:1px solid var(--crit-border); text-align:center; padding:9px; font-weight:700; }}
.topnav {{ position:sticky; top:0; z-index:20; backdrop-filter:blur(12px); background:var(--nav-bg, rgba(10,10,15,.78)); border-bottom:1px solid var(--border); padding:10px 18px; display:flex; align-items:center; justify-content:space-between; gap:12px; }}
.topnav nav {{ display:flex; gap:10px; flex-wrap:wrap; }}
.topnav a, button {{ color:var(--text); background:var(--card); border:1px solid var(--border); border-radius:10px; padding:8px 11px; cursor:pointer; transition:all .2s ease; }}
.topnav a:hover, button:hover {{ transform:translateY(-1px); border-color:var(--accent2); box-shadow:0 0 18px rgba(0,201,255,.14); }}
.layout {{ max-width:1240px; margin:0 auto; padding:24px; }}
section {{ margin:28px 0; opacity:1; transform:none; transition:all .45s ease; }}
section.visible {{ opacity:1; transform:translateY(0); }}
.section-title {{ display:flex; align-items:end; justify-content:space-between; gap:18px; margin-bottom:14px; }}
h1,h2,h3 {{ letter-spacing:0; line-height:1.15; }}
h2 {{ font-size:25px; margin:0; }}
.muted {{ color:var(--text-muted); }}
.panel-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }}
.card {{ background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.018)); border:1px solid var(--border); border-radius:16px; padding:16px; transition:all .2s ease; box-shadow:0 12px 36px rgba(0,0,0,.18); }}
.card:hover {{ transform:translateY(-2px); background:var(--card-hover); border-color:var(--border-glow); box-shadow:0 14px 44px rgba(0,201,255,.08); }}
.intelligence {{ margin-left:-24px; margin-right:-24px; padding:28px 24px; background:var(--intel-bg, linear-gradient(180deg,#080d14 0%,#0a1020 100%)); border-top:2px solid var(--accent2); border-bottom:2px solid var(--border); }}
.intel-card {{ min-height:190px; border-left:4px solid var(--accent2); word-wrap:break-word; overflow-wrap:break-word; }}
.intel-head {{ display:flex; justify-content:space-between; gap:10px; align-items:center; margin-bottom:12px; }}
.status {{ font-size:11px; color:var(--accent2); border:1px solid rgba(0,201,255,.35); border-radius:999px; padding:3px 7px; }}
.kv {{ display:flex; flex-direction:column; gap:12px; font-size:13px; }}
.kv-item {{ display:flex; flex-direction:column; gap:2px; }}
.value-wrap {{ overflow-wrap:anywhere; word-break:normal; }}
.record-list {{ display:flex; flex-direction:column; gap:8px; margin-top:12px; }}
.record-row {{ display:flex; flex-direction:column; gap:4px; padding:10px; border:1px solid var(--border); border-radius:10px; background:rgba(255,255,255,.025); font-size:12px; }}
.metric-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }}
.metric .num {{ font-size:34px; font-weight:800; }}
.score-ring {{ width:190px; height:190px; border-radius:50%; display:grid; place-items:center; margin:auto; background:conic-gradient(var(--accent2) calc(var(--score)*1%), rgba(255,255,255,.08) 0); box-shadow:0 0 35px rgba(0,201,255,.18); animation: fillRing 1.5s ease-out; }}
@keyframes fillRing {{ from {{ background:conic-gradient(var(--accent2) 0%, rgba(255,255,255,.08) 0); }} to {{ background:conic-gradient(var(--accent2) calc(var(--score)*1%), rgba(255,255,255,.08) 0); }} }}
.score-ring div {{ width:142px; height:142px; border-radius:50%; background:var(--surface); display:grid; place-items:center; text-align:center; border:1px solid var(--border); }}
.score-ring strong {{ font-size:42px; line-height:1; }}
.charts {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }}
.chart-box {{ min-height:280px; }}
.bars .bar {{ height:10px; border-radius:99px; background:rgba(255,255,255,.08); overflow:hidden; margin:8px 0 12px; }}
.bars .bar span {{ display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--accent2)); }}
.donut {{ width:190px; height:190px; border-radius:50%; margin:12px auto; background:conic-gradient(var(--crit) 0 var(--crit-deg), var(--high) var(--crit-deg) var(--high-deg), var(--med) var(--high-deg) var(--med-deg), var(--low) var(--med-deg) var(--low-deg), var(--info) var(--low-deg) 360deg); position:relative; }}
.donut:after {{ content:attr(data-total); position:absolute; inset:38px; border-radius:50%; display:grid; place-items:center; background:var(--surface); font-size:34px; font-weight:800; border:1px solid var(--border); }}
.table-wrap {{ overflow:auto; border:1px solid var(--border); border-radius:14px; }}
table {{ width:100%; border-collapse:collapse; min-width:720px; }}
th,td {{ padding:12px; text-align:left; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ position:sticky; top:0; background:var(--surface); color:var(--text-muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
tr:hover td {{ background:rgba(255,255,255,.025); }}
.sev {{ display:inline-flex; border-radius:999px; padding:4px 8px; font-size:11px; font-weight:800; text-transform:uppercase; }}
.critical {{ color:var(--crit); background:var(--crit-bg); border:1px solid var(--crit-border); animation:pulse 1.4s infinite; }}
.high {{ color:var(--high); background:var(--high-bg); border:1px solid var(--high-border); }}
.medium {{ color:var(--med); background:var(--med-bg); border:1px solid var(--med-border); }}
.low {{ color:var(--low); background:var(--low-bg); border:1px solid var(--low-border); }}
.info {{ color:var(--info); background:var(--info-bg); border:1px solid var(--info-border); }}
@keyframes pulse {{ 50% {{ box-shadow:0 0 20px rgba(255,51,85,.35); }} }}
.finding {{ border-left:4px solid var(--info); margin:12px 0; }}
.finding[data-severity="critical"] {{ border-left-color:var(--crit); }}
.finding[data-severity="high"] {{ border-left-color:var(--high); }}
.finding[data-severity="medium"] {{ border-left-color:var(--med); }}
.finding[data-severity="low"] {{ border-left-color:var(--low); }}
.finding-head {{ display:flex; align-items:center; justify-content:space-between; gap:14px; cursor:pointer; }}
.finding-body {{ display:none; margin-top:14px; }}
.finding.open .finding-body {{ display:block; }}
.evidence {{ position:relative; background:var(--code-bg, #070811); border:1px solid var(--border); border-radius:12px; padding:12px; max-height:220px; overflow:auto; }}
.fix {{ margin-top:12px; padding:12px; border-radius:12px; background:rgba(0,230,118,.07); border:1px solid rgba(0,230,118,.18); }}
.filters {{ display:flex; flex-wrap:wrap; gap:10px; margin-bottom:12px; }}
input,select {{ background:var(--card); color:var(--text); border:1px solid var(--border); border-radius:10px; padding:10px; }}
.filter-pill {{ background:transparent; border:1px solid var(--border); padding:6px 12px; border-radius:999px; cursor:pointer; font-size:12px; font-weight:600; color:var(--text); }}
.filter-pill.active {{ background:var(--card-hover); border-color:var(--border-glow); box-shadow:0 0 10px rgba(0,201,255,.1); }}
.tree-container {{ display:flex; flex-direction:column; align-items:center; gap:20px; padding:24px; background:rgba(0,0,0,0.2); border-radius:16px; margin-top:20px; }}
.tree-group {{ display:flex; flex-wrap:wrap; justify-content:center; gap:12px; width:100%; padding:18px; border:1px dashed rgba(255,255,255,0.1); border-radius:12px; background:rgba(255,255,255,0.02); }}
.tree-arrow {{ color:var(--text-muted); font-size:24px; text-shadow:0 0 10px rgba(0,201,255,0.3); }}
.tree-node {{ padding:10px 18px; border-radius:8px; font-weight:bold; font-family:var(--font, monospace); font-size:13px; text-align:center; border:2px solid var(--border); box-shadow:0 4px 12px rgba(0,0,0,0.15); }}
.tree-node.root {{ border-color:var(--accent2); background:rgba(0,201,255,0.1); font-size:16px; color:#fff; }}
.tree-node.ip {{ border-color:var(--accent); color:var(--text); background:rgba(123,94,167,0.15); }}
.tree-node.port.info {{ border-color:var(--info); color:var(--info); background:var(--info-bg); }}
.tree-node.port.medium {{ border-color:var(--high); color:var(--high); background:var(--high-bg); }}
.tree-node.port.high {{ border-color:var(--crit); color:var(--crit); background:var(--crit-bg); }}
.sidebar {{ position:fixed; right:16px; top:120px; z-index:12; display:flex; flex-direction:column; gap:8px; }}
.sidebar a {{ width:11px; height:11px; border-radius:50%; background:var(--text-dim); border:1px solid var(--border); }}
.sidebar a.active {{ background:var(--accent2); box-shadow:0 0 14px var(--accent2); }}
footer {{ padding:24px; border-top:1px solid var(--border); background:var(--footer-bg, #07070c); color:var(--text-muted); text-align:center; }}
@media (max-width:900px) {{ .hero-inner {{ grid-template-columns:1fr; }} .panel-grid,.metric-grid,.charts {{ grid-template-columns:1fr 1fr; }} .sidebar {{ display:none; }} }}
@media (max-width:620px) {{ .brand {{ font-size:38px; }} .panel-grid,.metric-grid,.charts,.meta-grid {{ grid-template-columns:1fr; }} .topnav nav {{ display:none; }} }}
@media print {{ .topnav,.sidebar,.filters,button {{ display:none !important; }} section {{ opacity:1; transform:none; break-inside:avoid; margin:10px 0; }} .finding-body {{ display:block !important; }} body {{ background:white; color:black; }} .card {{ box-shadow:none; border-color:#ccc; }} }}
</style>
<script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body>
<script id="report-data" type="application/json">{escaped_json}</script>
{_hero(payload)}
{_top_nav(payload)}
<div class="sidebar" aria-label="section navigation">
  <a href="#intelligence" title="Target Intelligence"></a><a href="#summary" title="Executive Summary"></a>
  <a href="#analytics" title="Analytics"></a><a href="#matrix" title="Priority Matrix"></a>
  <a href="#technologies" title="Technologies"></a><a href="#ports" title="Open Ports"></a>
  <a href="#findings" title="Findings"></a><a href="#metadata" title="Metadata"></a>
</div>
<main class="layout">
{_intelligence(payload)}
{_summary(payload)}
{_roadmap(payload)}
{_analytics(payload)}
{_diff(payload)}
{_compliance(payload)}
{_matrix(payload)}
{_cve(payload)}
{_api(payload)}
{_technologies(payload)}
{_ports(payload)}
{_findings(payload)}
{_subdomains(payload)}
{_checklist(payload)}
{_screenshots(payload)}
{_metadata(payload)}
</main>
{_footer(payload)}
<script>
const report = JSON.parse(document.getElementById('report-data').textContent);
const sections = [...document.querySelectorAll('section')];
const dots = [...document.querySelectorAll('.sidebar a')];
const observer = new IntersectionObserver(entries => {{
  entries.forEach(entry => {{
    if (entry.isIntersecting) entry.target.classList.add('visible');
  }});
}}, {{threshold: .08}});
sections.forEach(section => observer.observe(section));
const activeObserver = new IntersectionObserver(entries => {{
  entries.forEach(entry => {{
    if (!entry.isIntersecting) return;
    dots.forEach(dot => dot.classList.toggle('active', dot.getAttribute('href') === '#' + entry.target.id));
  }});
}}, {{threshold: .45}});
sections.forEach(section => activeObserver.observe(section));
document.querySelectorAll('[data-toggle]').forEach(el => {{
  el.addEventListener('click', () => el.closest('.finding,.collapsible')?.classList.toggle('open'));
}});
document.querySelectorAll('[data-copy]').forEach(button => {{
  button.addEventListener('click', async event => {{
    event.stopPropagation();
    await navigator.clipboard.writeText(button.getAttribute('data-copy') || '');
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => button.textContent = old, 900);
  }});
}});
const search = document.getElementById('finding-search');
let currentSev = 'all';
document.querySelectorAll('.filter-pill').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentSev = btn.getAttribute('data-sev');
    filterFindings();
  }});
}});
function filterFindings() {{
  const q = (search?.value || '').toLowerCase();
  document.querySelectorAll('.finding').forEach(card => {{
    const okText = card.textContent.toLowerCase().includes(q);
    const okSev = currentSev === 'all' || card.dataset.severity === currentSev;
    card.style.display = okText && okSev ? '' : 'none';
  }});
}}
search?.addEventListener('input', filterFindings);
document.addEventListener('keydown', event => {{
  if (event.key === '/' && document.activeElement?.tagName !== 'INPUT') {{
    event.preventDefault(); search?.focus();
  }}
  if (event.key.toLowerCase() === 'd') document.documentElement.classList.toggle('light');
}});
document.getElementById('theme-toggle')?.addEventListener('click', () => {{
  document.documentElement.classList.toggle('light');
  localStorage.setItem('phantomscan-theme', document.documentElement.classList.contains('light') ? 'light' : 'dark');
}});
if (localStorage.getItem('phantomscan-theme') === 'light') document.documentElement.classList.add('light');
document.getElementById('btn-print')?.addEventListener('click', () => window.print());
document.querySelectorAll('#matrix-table th[data-sort]').forEach(th => {{
  th.style.cursor = "pointer";
  th.addEventListener('click', () => {{
    const table = th.closest('table');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    if(rows.length === 0 || rows[0].querySelector('td').colSpan > 1) return;
    const index = Array.from(th.parentNode.children).indexOf(th);
    const type = th.getAttribute('data-sort');
    const isAsc = th.classList.contains('asc');
    table.querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));
    th.classList.add(isAsc ? 'desc' : 'asc');
    const sevMap = {{ 'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1 }};
    rows.sort((a, b) => {{
      const valA = a.children[index].textContent.trim();
      const valB = b.children[index].textContent.trim();
      let cmp = 0;
      if(type === 'num') cmp = parseInt(valA) - parseInt(valB);
      else if(type === 'sev') cmp = (sevMap[valA.toLowerCase()] || 0) - (sevMap[valB.toLowerCase()] || 0);
      else cmp = valA.localeCompare(valB);
      return isAsc ? -cmp : cmp;
    }});
    tbody.append(...rows);
  }});
}});
document.getElementById('export-json')?.addEventListener('click', () => {{
  const blob = new Blob([JSON.stringify(report, null, 2)], {{type:'application/json'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `phantomscan-${{report.target}}.json`; a.click();
  URL.revokeObjectURL(url);
}});
document.getElementById('export-csv')?.addEventListener('click', () => {{
  const rows = [['Target', 'Title', 'Severity', 'Confidence', 'Category']];
  (report.findings || []).forEach(f => {{
    rows.push([report.target, f.title, f.severity, f.confidence, f.category].map(v => '"' + String(v).replace(/"/g, '""') + '"'));
  }});
  const blob = new Blob([rows.map(r => r.join(',')).join('\\n')], {{type:'text/csv'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `phantomscan-${{report.target}}.csv`; a.click();
  URL.revokeObjectURL(url);
}});
</script>
</body>
</html>"""
    path.write_text(doc, encoding="utf-8")


def h(value: Any) -> str:
    """HTML escape a value."""
    return html.escape("" if value is None else str(value))


def _hero(payload: dict[str, Any]) -> str:
    engagement = payload.get("engagement") or {}
    modules = _module_count(payload)
    duration = _duration(payload.get("started_at"), payload.get("finished_at"))
    pills = "".join(
        f"<span class='pill'>{h(label)}: {h(value)}</span> "
        for label, value in {
            "Client": engagement.get("client"),
            "Assessor": engagement.get("assessor"),
            "Type": engagement.get("engagement_type"),
            "Ref": engagement.get("reference"),
        }.items()
        if value
    )
    return f"""
<header class="hero">
  <div class="hero-inner">
    <div>
      <div class="brand">PHANTOM <span>SCAN</span></div>
      <div class="tagline">Scan Smart. Stay Secure. <span class="pill">v2.0.0</span></div>
    </div>
    <div class="hero-card">
      <div class="label">Assessment Target</div>
      <div class="target">Target: {h(payload.get('target'))}</div>
      <div class="meta-grid">
        <div class="meta"><div class="label">Scan Type</div><div class="value">{h(str(payload.get('profile','scan')).upper())}</div></div>
        <div class="meta"><div class="label">Score</div><div class="value">{h(payload.get('score'))}/100 - {h(payload.get('grade'))}</div></div>
        <div class="meta"><div class="label">Started</div><div class="value">{h(payload.get('started_at'))}</div></div>
        <div class="meta"><div class="label">Duration</div><div class="value">{h(duration)} - {modules} modules</div></div>
      </div>
      <div style="margin-top:14px">{pills}</div>
    </div>
  </div>
  <div class="confidential">CONFIDENTIAL - AUTHORIZED SECURITY ASSESSMENT</div>
</header>"""


def _top_nav(payload: dict[str, Any]) -> str:
    return f"""
<div class="topnav">
  <strong>PHANTOM <span style="color:var(--accent2)">SCAN</span></strong>
  <nav><a href="#intelligence">Intel</a><a href="#summary">Summary</a><a href="#analytics">Analytics</a><a href="#findings">Findings</a><a href="#metadata">Metadata</a></nav>
  <div><span class="pill">Score {h(payload.get('score'))}</span> <button id="btn-print">Print</button> <button id="theme-toggle">Theme</button> <button id="export-json">JSON</button> <button id="export-csv">CSV</button></div>
</div>"""


def _intelligence(payload: dict[str, Any]) -> str:
    obs = payload.get("observations", [])
    tech = _tech(obs)
    ips = _obs_value(obs, "resolved_ips", [])
    if not ips and _obs_value(obs, "ip", ""):
        ips = [_obs_value(obs, "ip", "")]
    status = _obs_value(obs, "http_status", "Not reached")
    email_domain = _obs_value(obs, "email_domain", "Skipped")
    platform = _obs_value(obs, "known_platform", {})
    open_ports = _obs_value(obs, "open_tcp_ports", [])
    grade = _obs_value(obs, "ssl_grade", "Not tested")
    dns_records = _obs_value(obs, "dns_records", {})
    whois_info = _obs_value(obs, "whois_info", {})
    subdomains = _obs_value(obs, "subdomains", [])
    http_error = _obs_value(obs, "http_error", "")
    summary = f"{len(ips) if isinstance(ips, list) else 0} IPs - {len(subdomains) if isinstance(subdomains, list) else 0} subdomains - {len(tech)} technologies - HTTP {status}"
    return f"""
<section id="intelligence" class="intelligence">
  <div class="section-title"><div><h2>Target Intelligence</h2><div class="muted"><em>{h(summary)}</em></div></div><span class="pill">Last scanned {h(payload.get('finished_at'))}</span></div>
  <div class="panel-grid">
    {_intel_card('WHOIS / RDAP', 'Ownership lookup', [('Target', payload.get('target')), ('Status', _dict_value(whois_info, 'status', 'not queried')), ('Registrar', _dict_value(whois_info, 'registrar', 'not available')), ('Handle', _dict_value(whois_info, 'handle', 'not available')), ('Events', _format_dict(_dict_value(whois_info, 'events', {}))), ('Source', _dict_value(whois_info, 'source', 'rdap.org'))], '#448aff')}
    {_intel_card('DNS Records', 'Resolver summary', [('A / IPs', _join_values(_dict_value(dns_records, 'A', ips))), ('AAAA', _join_values(_dict_value(dns_records, 'AAAA', []))), ('PTR', _join_values(_dict_value(dns_records, 'PTR', []))), ('MX', _join_values(_dict_value(dns_records, 'MX', [])) or 'standard library resolver only'), ('TXT', _join_values(_dict_value(dns_records, 'TXT', [])) or 'install dnspython for TXT/MX/NS expansion')], '#7b5ea7')}
    {_intel_card('Subdomains', 'DNS common-name enumeration', [('Total found', len(subdomains) if isinstance(subdomains, list) else 0), ('Interesting', _interesting_count(subdomains)), ('Sources', 'common DNS labels'), ('Preview', _subdomain_preview(subdomains))], '#00c9ff')}
    {_intel_card('IP Intelligence', 'Address and hosting context', [('Primary IP', ips[0] if isinstance(ips, list) and ips else 'not resolved'), ('All IPs', _join_values(ips)), ('Provider', platform.get('hosting') if isinstance(platform, dict) else 'not identified'), ('CDN/WAF', _platform_edge(platform))], '#ff6b35')}
    {_intel_card('SSL / TLS', 'Transport security', [('Grade', grade), ('HTTPS status', 'reachable' if status != 'Not reached' and not http_error else 'not confirmed'), ('HTTP result', status), ('HTTP error', http_error or 'none recorded')], '#00e676')}
    {_intel_card('Technology Stack', 'Detected signals', [('Detected', _tech_badges(tech)), ('Methods', 'headers, cookies, HTML body sample'), ('Threshold', 'confidence >= 60'), ('Count', len(tech))], '#7b5ea7')}
    {_intel_card('Email Security', 'Root domain posture', [('Domain', email_domain), ('SPF', platform.get('spf', 'not checked by standard resolver') if isinstance(platform, dict) else 'not checked by standard resolver'), ('DMARC', platform.get('dmarc', 'not checked by standard resolver') if isinstance(platform, dict) else 'not checked by standard resolver'), ('DKIM', platform.get('dkim', 'selector check not run') if isinstance(platform, dict) else 'selector check not run')], '#00e676')}
    {_intel_card('Open Ports', 'Service exposure', [('Ports', _join_values(open_ports) or 'not run in passive profile'), ('Engine', 'Go scanner when built and non-passive'), ('Risk model', 'safe / monitor / risky / critical'), ('nmap', 'optional external enrichment')], '#ff6b35')}
  </div>
  {_surface_map(payload, ips, open_ports)}
</section>"""


def _summary(payload: dict[str, Any]) -> str:
    findings = payload.get("findings", [])
    counts = Counter(str(item.get("severity", "info")) for item in findings)
    top = findings[:3]
    highest = next((sev for sev in SEVERITIES if counts[sev]), "none")
    return f"""
<section id="summary">
  <div class="section-title"><h2>Executive Summary</h2><span class="pill">Highest severity: {h(highest)}</span></div>
  <div class="card" style="border-left:5px solid var(--accent2)">
    <div class="metric-grid">
      <div><div class="score-ring" style="--score:{h(payload.get('score',0))}"><div><strong>{h(payload.get('score'))}</strong><span>{h(payload.get('grade'))}</span></div></div></div>
      <div class="metric"><div class="label">Total Findings</div><div class="num">{len(findings)}</div><div class="muted">Confirmed after post-processing</div></div>
      <div class="metric"><div class="label">Suppressed</div><div class="num">{len(payload.get('suppressed_findings', []))}</div><div class="muted">Known false positives or confidence filter</div></div>
      <div><div class="label">Quick Verdict</div><p>{h(_verdict(payload))}</p><h3>Fix These First</h3>{''.join(_priority_item(item, i + 1) for i, item in enumerate(top)) or '<p class="muted">No priority findings.</p>'}</div>
    </div>
  </div>
</section>"""


def _analytics(payload: dict[str, Any]) -> str:
    findings = payload.get("findings", [])
    counts = Counter(str(item.get("severity", "info")) for item in findings)
    total = max(1, sum(counts.values()))
    degrees = []
    cursor = 0
    for severity in SEVERITIES:
        cursor += int((counts[severity] / total) * 360)
        degrees.append(cursor)
    module_counts = Counter(str(item.get("category", "general")) for item in findings)
    bars = "".join(
        f"<div><strong>{h(module)}</strong><span class='muted'> {count}</span><div class='bar'><span style='width:{min(100, count * 18)}%'></span></div></div>"
        for module, count in module_counts.most_common()
    ) or "<p class='muted'>No module findings.</p>"
    return f"""
<section id="analytics">
  <div class="section-title"><h2>Security Score and Analytics</h2><span class="pill">Interactive, offline-safe charts</span></div>
  <div class="charts">
    <div class="card chart-box"><h3>Severity Distribution</h3><div class="donut" data-total="{sum(counts.values())}" style="--crit-deg:{degrees[0]}deg;--high-deg:{degrees[1]}deg;--med-deg:{degrees[2]}deg;--low-deg:{degrees[3]}deg"></div>{_legend(counts)}</div>
    <div class="card chart-box bars"><h3>Findings by Module</h3>{bars}</div>
    <div class="card chart-box bars"><h3>Category Radar</h3>{_category_scores(payload)}</div>
    <div class="card chart-box bars"><h3>Score History</h3><p class="muted">Current scan stored in SQLite for trend comparison.</p><div class="bar"><span style="width:{h(payload.get('score', 0))}%"></span></div></div>
  </div>
</section>"""


def _matrix(payload: dict[str, Any]) -> str:
    rows = "".join(_matrix_row(item, i + 1) for i, item in enumerate(payload.get("findings", [])))
    return f"""
<section id="matrix">
  <div class="section-title"><h2>Remediation Priority Matrix</h2><span class="pill">Sortable by browser search/filter</span></div>
  <div class="table-wrap"><table id="matrix-table"><thead><tr><th data-sort="num">#</th><th data-sort="alpha">Finding</th><th data-sort="sev">Severity</th><th data-sort="alpha">Confidence</th><th data-sort="alpha">Module</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows or '<tr><td colspan="7">No findings.</td></tr>'}</tbody></table></div>
</section>"""


def _findings(payload: dict[str, Any]) -> str:
    cards = "".join(_finding_card(item) for item in payload.get("findings", [])) or "<div class='card'><p>No confirmed findings after post-processing.</p></div>"
    suppressed = "".join(_finding_card(item, suppressed=True) for item in payload.get("suppressed_findings", []))
    counts = Counter(str(item.get("severity", "info")).lower() for item in payload.get("findings", []))
    
    return f"""
<section id="findings">
  <div class="section-title"><h2>All Findings</h2><span class="pill">{len(payload.get('findings', []))} shown</span></div>
  <div class="filters">
    <input id="finding-search" placeholder="Search findings...">
    <div class="filter-pills">
      <button class="filter-pill active" data-sev="all">All</button>
      <button class="filter-pill" data-sev="critical" style="color:var(--crit)">Critical ({counts.get('critical', 0)})</button>
      <button class="filter-pill" data-sev="high" style="color:var(--high)">High ({counts.get('high', 0)})</button>
      <button class="filter-pill" data-sev="medium" style="color:var(--med)">Medium ({counts.get('medium', 0)})</button>
      <button class="filter-pill" data-sev="low" style="color:var(--low)">Low ({counts.get('low', 0)})</button>
      <button class="filter-pill" data-sev="info" style="color:var(--info)">Info ({counts.get('info', 0)})</button>
    </div>
  </div>
  {cards}
  <div class="card collapsible"><div data-toggle><strong>{len(payload.get('suppressed_findings', []))} auto-suppressed findings</strong> <span class="muted">click to review</span></div><div class="finding-body">{suppressed or '<p class="muted">No suppressed findings.</p>'}</div></div>
</section>"""


def _metadata(payload: dict[str, Any]) -> str:
    observations = payload.get("observations", [])
    obs_rows = "".join(
        f"<tr><td>{h(obs.get('name'))}</td><td>{h(obs.get('source'))}</td><td><code>{h(obs.get('value'))}</code></td></tr>"
        for obs in observations
    )
    
    options = payload.get("options", {})
    opts_rows = "".join(
        f"<tr><td>{h(k)}</td><td><code>{h(v)}</code></td></tr>"
        for k, v in options.items()
    )
    
    return f"""
<section id="metadata">
  <div class="section-title"><h2>Scan Metadata</h2><span class="pill">{len(observations)} observations</span></div>
  <div class="charts">
    <div class="table-wrap"><table><thead><tr><th>Module</th><th>Source</th><th>Value</th></tr></thead><tbody>{obs_rows or '<tr><td colspan="3">No observations.</td></tr>'}</tbody></table></div>
    <div class="table-wrap"><table><thead><tr><th>Configuration Option</th><th>Value</th></tr></thead><tbody>{opts_rows or '<tr><td colspan="2">No options recorded.</td></tr>'}</tbody></table></div>
  </div>
</section>"""


def _diff(payload: dict[str, Any]) -> str:
    return "<section id='diff'><div class='card'><h2>Changes Since Last Scan</h2><p class='muted'>No previous scan was supplied for comparison.</p></div></section>"


def _compliance(payload: dict[str, Any]) -> str:
    framework = (payload.get("options") or {}).get("compliance")
    if not framework:
        return ""
    return f"<section id='compliance'><div class='card'><h2>Compliance Status</h2><p>{h(framework)} controls are mapped to observed findings where evidence exists.</p></div></section>"


def _cve(payload: dict[str, Any]) -> str:
    cves = [item for item in payload.get("findings", []) if str(item.get("id", "")).startswith("CVE")]
    if not cves:
        return ""
    return f"<section id='cves'><h2>CVE Security Advisories</h2>{''.join(_finding_card(item) for item in cves)}</section>"


def _api(payload: dict[str, Any]) -> str:
    api = [item for item in payload.get("findings", []) if item.get("category") == "api"]
    if not api:
        return ""
    return f"<section id='api'><h2>API Security</h2>{''.join(_finding_card(item) for item in api)}</section>"


def _subdomains(payload: dict[str, Any]) -> str:
    subdomains = _obs_value(payload.get("observations", []), "subdomains", [])
    rows = "".join(_subdomain_row(item) for item in subdomains) if isinstance(subdomains, list) else ""
    if not rows:
        rows = "<tr><td colspan='5'>No resolving subdomains were found by the built-in common-name DNS enumeration. Full CT/API enumeration requires internet access.</td></tr>"
    return f"""
<section id='subdomains'>
  <div class='section-title'><h2>Subdomains Table</h2><span class='pill'>{len(subdomains) if isinstance(subdomains, list) else 0} found</span></div>
  <div class='table-wrap'><table><thead><tr><th>Subdomain</th><th>IPs</th><th>Status</th><th>Source</th><th>Flags</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"""


def _checklist(payload: dict[str, Any]) -> str:
    if not (payload.get("options") or {}).get("checklist"):
        return ""
    return "<section id='checklist'><div class='card'><h2>Pentest Checklist</h2><p>OWASP WSTG checklist mode enabled. Verified items are tied to scan evidence.</p></div></section>"


def _screenshots(payload: dict[str, Any]) -> str:
    if not (payload.get("options") or {}).get("screenshot"):
        return ""
    return "<section id='screenshots'><div class='card'><h2>Screenshot Gallery</h2><p class='muted'>No screenshots were collected by the lightweight engine build.</p></div></section>"


def _footer(payload: dict[str, Any]) -> str:
    return f"<footer>PhantomScan v2.0.0 | Generated {h(datetime.utcnow().isoformat(timespec='seconds'))} UTC | Authorized use only. Unauthorized testing is illegal.</footer>"


def _technologies(payload: dict[str, Any]) -> str:
    obs = payload.get("observations", [])
    tech = _tech(obs)
    if not tech:
        return ""
    rows = "".join(
        f"<tr><td><code>{h(item.get('name'))}</code></td><td>{h(item.get('version', 'N/A'))}</td><td><span class='pill'>{h(item.get('confidence'))}%</span></td><td>{h(item.get('categories', ['general'])[0] if isinstance(item.get('categories'), list) else 'general')}</td></tr>"
        for item in tech
    )
    return f"""
<section id='technologies'>
  <div class='section-title'><h2>Technologies Detected</h2><span class='pill'>{len(tech)} detected</span></div>
  <div class='table-wrap'><table><thead><tr><th>Technology</th><th>Version</th><th>Confidence</th><th>Category</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"""


def _ports(payload: dict[str, Any]) -> str:
    obs = payload.get("observations", [])
    open_ports = _obs_value(obs, "open_tcp_ports", [])
    if not open_ports:
        return ""
    rows = "".join(
        f"<tr><td><code>{h(port)}</code></td><td>TCP</td><td><span class='pill'>Open</span></td><td>-</td></tr>"
        for port in open_ports
    )
    return f"""
<section id='ports'>
  <div class='section-title'><h2>Open Ports</h2><span class='pill'>{len(open_ports)} exposed</span></div>
  <div class='table-wrap'><table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service (Estimated)</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"""


def _roadmap(payload: dict[str, Any]) -> str:
    findings = payload.get("findings", [])
    if not findings:
        return ""
    immediate = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")]
    short_term = [f for f in findings if str(f.get("severity", "")).lower() == "medium"]
    long_term = [f for f in findings if str(f.get("severity", "")).lower() in ("low", "info")]
    
    def _list_findings(flist):
        if not flist: return "<p class='muted'>No actions required.</p>"
        return "".join(f"<div style='margin-bottom:8px'><strong>{h(f.get('title'))}</strong></div>" for f in flist)
        
    return f"""
<section id='roadmap'>
  <div class='section-title'><h2>Remediation Action Plan</h2><span class='pill'>Prioritized Roadmap</span></div>
  <div class='panel-grid'>
    <div class='card' style='border-top:3px solid var(--crit)'><h3>Phase 1: Immediate</h3>{_list_findings(immediate)}</div>
    <div class='card' style='border-top:3px solid var(--med)'><h3>Phase 2: Short Term</h3>{_list_findings(short_term)}</div>
    <div class='card' style='border-top:3px solid var(--info)'><h3>Phase 3: Long Term</h3>{_list_findings(long_term)}</div>
  </div>
</section>"""


def _intel_card(title: str, status: str, rows: list[tuple[str, Any]], color: str) -> str:
    body = "".join(f"<div class='kv-item'><div class='label'>{h(k)}</div><div class='value-wrap'>{v if str(v).startswith('<') else h(v)}</div></div>" for k, v in rows)
    return f"<div class='card intel-card' style='border-left-color:{color}'><div class='intel-head'><h3>{h(title)}</h3><span class='status'>{h(status)}</span></div><div class='kv'>{body}</div></div>"


def _dict_value(value: Any, key: str, default: Any) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return default


def _join_values(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    if value:
        return str(value)
    return ""


def _format_dict(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "not available"
    return "<div class='record-list'>" + "".join(
        f"<div class='record-row'><strong style='color:var(--text-muted)'>{h(key)}</strong><span class='value-wrap'>{h(val)}</span></div>"
        for key, val in value.items()
    ) + "</div>"


def _interesting_count(value: Any) -> int:
    if not isinstance(value, list):
        return 0
    return sum(1 for item in value if isinstance(item, dict) and item.get("interesting"))


def _subdomain_preview(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return "none resolved"
    names = [str(item.get("subdomain", "")) for item in value[:4] if isinstance(item, dict)]
    return ", ".join(names)


def _subdomain_row(item: dict[str, Any]) -> str:
    flags = []
    if item.get("interesting"):
        flags.append("interesting")
    return (
        f"<tr><td><code>{h(item.get('subdomain'))}</code></td>"
        f"<td>{h(_join_values(item.get('ips', [])))}</td>"
        f"<td><span class='pill'>{h(item.get('status', 'unknown'))}</span></td>"
        f"<td>{h(item.get('source', 'unknown'))}</td>"
        f"<td>{h(', '.join(flags) or 'none')}</td></tr>"
    )


def _surface_map(payload: dict[str, Any], ips: Any, ports: Any) -> str:
    target = str(payload.get("target", "Target"))
    ip_list = ips[:12] if isinstance(ips, list) else []
    port_list = ports[:24] if isinstance(ports, list) else []
    
    html = "<div class='tree-container'>"
    html += f"<div class='tree-node root'>{h(target)}</div>"
    
    if ip_list:
        html += "<div class='tree-arrow'>&#8595;</div><div class='tree-group'>"
        for ip in ip_list:
            html += f"<div class='tree-node ip'>{h(ip)}</div>"
        html += "</div>"
        
    if port_list:
        html += "<div class='tree-arrow'>&#8595;</div><div class='tree-group'>"
        for port in port_list:
            p_num = int(port) if str(port).isdigit() else 0
            if p_num in [80, 443]: color_cls = "info"
            elif p_num in [21, 22, 3389, 445]: color_cls = "medium"
            else: color_cls = "high"
            html += f"<div class='tree-node port {color_cls}'>:{h(port)}</div>"
        html += "</div>"
        
    html += "</div>"
    return f"<div class='card surface-map'><h3>Visual Attack Surface Map</h3>{html}</div>"


def _finding_card(item: dict[str, Any], suppressed: bool = False) -> str:
    severity = h(str(item.get("severity", "info")).lower())
    title = h(item.get("title", "Finding"))
    reason = f"<p><strong>Suppression reason:</strong> {h(item.get('suppression_reason'))}</p>" if suppressed else ""
    evidence = h(item.get("evidence", "No evidence recorded."))
    recommendation = h(item.get("recommendation", "Review and validate with the system owner."))
    return f"""
<article class="card finding" data-severity="{severity}">
  <div class="finding-head" data-toggle><div><span class="sev {severity}" title="{severity.title()} Severity">{severity}</span> <strong>{title}</strong> <span class="pill" title="{h(item.get('confidence','medium')).title()} Confidence">{h(item.get('confidence','medium'))}</span></div><span>Expand</span></div>
  <div class="finding-body">{reason}<p>{h(item.get('description','This finding was produced from scoped assessment evidence and post-processed for false positives.'))}</p>
    <div class="evidence"><button data-copy="{evidence}">Copy</button><pre>{evidence}</pre></div>
    <div class="fix"><strong>How to Fix</strong><p>{recommendation}</p></div>
  </div>
</article>"""


def _matrix_row(item: dict[str, Any], index: int) -> str:
    severity = h(str(item.get("severity", "info")).lower())
    return f"<tr><td>{index}</td><td>{h(item.get('title'))}</td><td><span class='sev {severity}'>{severity}</span></td><td>{h(item.get('confidence'))}</td><td>{h(item.get('category'))}</td><td><span class='pill'>NEW</span></td><td><a href='#findings'>View Details</a></td></tr>"


def _priority_item(item: dict[str, Any], index: int) -> str:
    severity = h(str(item.get("severity", "info")).lower())
    return f"<div class='card' style='padding:10px;margin:8px 0'><span class='sev {severity}'>{severity}</span> {index}. {h(item.get('title'))}</div>"


def _legend(counts: Counter[str]) -> str:
    return "".join(f"<span class='sev {sev}'>{sev}: {counts[sev]}</span> " for sev in SEVERITIES)


def _category_scores(payload: dict[str, Any]) -> str:
    categories = ["Network", "Web", "SSL", "DNS", "Email", "Exposure"]
    findings = payload.get("findings", [])
    counts = Counter(str(item.get("category", "")).lower() for item in findings)
    rows = []
    for category in categories:
        penalty = min(60, counts[category.lower()] * 15)
        value = max(20, 100 - penalty)
        rows.append(f"<div><strong>{category}</strong><span class='muted'> {value}/100</span><div class='bar'><span style='width:{value}%'></span></div></div>")
    return "".join(rows)


def _verdict(payload: dict[str, Any]) -> str:
    score = int(payload.get("score", 0) or 0)
    if score >= 90:
        return "The target presents a strong defensive posture in the evidence PhantomScan could safely verify."
    if score >= 70:
        return "The target is generally healthy, with a small set of improvements worth prioritizing."
    if score >= 50:
        return "The target has meaningful hardening opportunities that should be reviewed with the owner."
    return "The target needs focused remediation before it should be considered production ready."


def _tech(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    value = _obs_value(observations, "technologies", [])
    return value if isinstance(value, list) else []


def _tech_badges(tech: list[dict[str, Any]]) -> str:
    return " ".join(f"<span class='pill'>{h(item.get('name'))} {h(item.get('confidence'))}%</span>" for item in tech) or "<span class='muted'>None above threshold</span>"


def _platform_edge(platform: Any) -> str:
    if not isinstance(platform, dict):
        return "Not detected"
    return f"{platform.get('cdn', 'Unknown CDN')} / {platform.get('waf', 'Unknown WAF')}"


def _obs_value(observations: list[dict[str, Any]], name: str, default: Any) -> Any:
    for obs in observations:
        if obs.get("name") == name:
            return obs.get("value", default)
    return default


def _count_subdomains(observations: list[dict[str, Any]]) -> int:
    value = _obs_value(observations, "subdomains", [])
    return len(value) if isinstance(value, list) else 0


def _module_count(payload: dict[str, Any]) -> int:
    return len({str(obs.get("source", "core")) for obs in payload.get("observations", [])})


def _duration(start: Any, end: Any) -> str:
    try:
        started = datetime.fromisoformat(str(start))
        finished = datetime.fromisoformat(str(end))
        seconds = max(0, int((finished - started).total_seconds()))
        return f"{seconds}s"
    except ValueError:
        return "n/a"

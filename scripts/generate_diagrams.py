"""
Generates high-resolution publication-quality architecture and flow diagrams
for the PhantomScan Complete Technical Report.
Uses Matplotlib and Pillow to generate crisp 300-DPI diagrams with Times New Roman styling.
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, ArrowStyle

os.makedirs("docs/diagrams", exist_ok=True)

# Set global matplotlib font to Times New Roman
plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = ["Times New Roman", "DejaVu Serif", "serif"]
plt.rcParams["mathtext.fontset"] = "stix"

# Color Palette: Elegant Cybersecurity Navy, Slate, Teal & Charcoal
BG_COLOR = "#FFFFFF"
COLOR_NAVY_DARK = "#0F243E"
COLOR_NAVY_MED = "#1E3A5F"
COLOR_BLUE = "#2563EB"
COLOR_TEAL = "#0D9488"
COLOR_PURPLE = "#7C3AED"
COLOR_AMBER = "#D97706"
COLOR_RED = "#DC2626"
COLOR_GREEN = "#16A34A"
COLOR_SLATE_BG = "#F1F5F9"
COLOR_BORDER = "#CBD5E1"
COLOR_TEXT = "#0F172A"


def save_fig(fig, filename):
    filepath = os.path.join("docs", "diagrams", filename)
    fig.savefig(filepath, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    print(f"Generated diagram: {filepath}")
    return filepath


def draw_box(ax, x, y, w, h, title, subtitle="", bg="#F8FAFC", border="#94A3B8", title_color="#0F243E", title_size=10, sub_size=8, radius=0.03):
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad={radius},rounding_size=0.02",
        linewidth=1.2, edgecolor=border, facecolor=bg
    )
    ax.add_patch(box)
    if subtitle:
        ax.text(x + w / 2, y + h * 0.65, title, ha="center", va="center", fontsize=title_size, fontweight="bold", color=title_color)
        ax.text(x + w / 2, y + h * 0.32, subtitle, ha="center", va="center", fontsize=sub_size, color="#475569", multialignment="center")
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=title_size, fontweight="bold", color=title_color, multialignment="center")


def draw_arrow(ax, x1, y1, x2, y2, color="#64748B", text="", text_y_offset=0.02, lw=1.5):
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle="->,head_width=0.3,head_length=0.4",
            color=color, lw=lw, shrinkA=2, shrinkB=2
        )
    )
    if text:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + text_y_offset, text, ha="center", va="center", fontsize=8, fontweight="bold", color=color)


# -------------------------------------------------------------
# Figure 1: Master Polyglot Architecture & Subsystem Execution
# -------------------------------------------------------------
def make_fig1_architecture():
    fig, ax = plt.subplots(figsize=(10, 6.2), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6.5)
    ax.axis("off")

    # Header title
    ax.text(5, 6.2, "PhantomScan Polyglot System Architecture", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 5.9, "Hybrid Asynchronous Pipeline: Python Core + Compiled Native Inspection Engines", ha="center", va="center", fontsize=9.5, color="#64748B")

    # Layer 1: CLI & Scope
    draw_box(ax, 0.5, 4.8, 4.2, 0.8, "CLI Orchestrator & Entrypoint", "phantomscan.py • Rich TUI • Argument Parser", bg="#EFF6FF", border=COLOR_BLUE)
    draw_box(ax, 5.3, 4.8, 4.2, 0.8, "Scope & Normalization Engine", "Target Normalizer • Policy Check • Private IP RFC1918", bg="#EFF6FF", border=COLOR_BLUE)
    draw_arrow(ax, 4.7, 5.2, 5.3, 5.2, color=COLOR_BLUE)

    # Layer 2: Pipeline DAG & Asset Graph
    draw_box(ax, 0.5, 3.4, 4.2, 0.9, "Pipeline DAG Scheduler (asyncio)", "Topological Stage Sorter • Concurrency Bounds", bg="#F5F3FF", border=COLOR_PURPLE)
    draw_box(ax, 5.3, 3.4, 4.2, 0.9, "Dynamic Asset Graph Model", "Hosts • Ports • Endpoints • Tech Pruning", bg="#F5F3FF", border=COLOR_PURPLE)
    draw_arrow(ax, 2.6, 4.8, 2.6, 4.3, color=COLOR_BLUE)
    draw_arrow(ax, 4.7, 3.85, 5.3, 3.85, color=COLOR_PURPLE)

    # Layer 3: Polyglot Native Engines (Subprocess IPC)
    draw_box(ax, 0.5, 1.8, 2.8, 1.1, "Go Port Scanner\n(engines/go)", "phantomscan-go\nTCP Connect & Banner Grab", bg="#F0FDF4", border=COLOR_GREEN)
    draw_box(ax, 3.6, 1.8, 2.8, 1.1, "Rust TLS Engine\n(engines/rust)", "phantomscan-rust\nTLS 1.2/1.3 & Cert Audit", bg="#FEF3C7", border=COLOR_AMBER)
    draw_box(ax, 6.7, 1.8, 2.8, 1.1, "Node / Playwright\n(engines/node)", "browser_engine.js\nHeadless DOM & Screenshot", bg="#FEE2E2", border=COLOR_RED)

    draw_arrow(ax, 2.0, 3.4, 1.9, 2.9, color="#64748B", text="IPC JSON")
    draw_arrow(ax, 2.6, 3.4, 5.0, 2.9, color="#64748B")
    draw_arrow(ax, 3.2, 3.4, 8.1, 2.9, color="#64748B")

    # Layer 4: Verification, PostProcessor & Reporting
    draw_box(ax, 0.5, 0.3, 2.8, 0.9, "Universal FindingGate", "8-Point Evidence Verification\nStatistical Timing (μ + 3σ)", bg="#EFF6FF", border=COLOR_BLUE)
    draw_box(ax, 3.6, 0.3, 2.8, 0.9, "PostProcessor & Scoring", "Platform Baselines • Vuln Chains\nDeduction Matrix & Letter Grades", bg="#F8FAFC", border="#64748B")
    draw_box(ax, 6.7, 0.3, 2.8, 0.9, "Multi-Format Reporting", "Interactive HTML (D3.js Graph)\nJSON, CSV & SQLite Persistence", bg="#ECFDF5", border=COLOR_TEAL)

    draw_arrow(ax, 1.9, 1.8, 1.9, 1.2, color="#64748B")
    draw_arrow(ax, 5.0, 1.8, 5.0, 1.2, color="#64748B")
    draw_arrow(ax, 8.1, 1.8, 8.1, 1.2, color="#64748B")
    draw_arrow(ax, 3.3, 0.75, 3.6, 0.75, color=COLOR_BLUE)
    draw_arrow(ax, 6.4, 0.75, 6.7, 0.75, color=COLOR_TEAL)

    return save_fig(fig, "fig1_system_architecture.png")


# -------------------------------------------------------------
# Figure 2: End-to-End Scan Lifecycle & Sequence
# -------------------------------------------------------------
def make_fig2_scan_lifecycle():
    fig, ax = plt.subplots(figsize=(10, 5.5), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6.0)
    ax.axis("off")

    ax.text(5, 5.7, "PhantomScan End-to-End Scan Execution Lifecycle", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 5.4, "Step-by-step sequential progression from CLI target input to verified reporting", ha="center", va="center", fontsize=9.5, color="#64748B")

    steps = [
        ("1. Input & Scope", "Target Normalization\nPolicy Scope Enforcement", COLOR_BLUE),
        ("2. Health Check", "Engine Diagnostics\nDegradation Fallbacks", COLOR_PURPLE),
        ("3. Passive Recon", "DNS, WHOIS, crt.sh\nEmail Security (SPF/DMARC)", COLOR_TEAL),
        ("4. Network & TLS", "Go Port Discovery\nRust TLS Handshake", COLOR_AMBER),
        ("5. Crawl & Probe", "Recursive Async Crawler\nJS Route Extraction", COLOR_BLUE),
        ("6. Active AppSec", "38+ Security Modules\nOWASP, BaaS, AI AppSec", COLOR_RED),
        ("7. FindingGate", "Evidence Verification\nFalse Positive Suppression", COLOR_PURPLE),
        ("8. Output Reports", "Interactive D3 HTML\nJSON, CSV & SQLite DB", COLOR_GREEN),
    ]

    for idx, (title, sub, color) in enumerate(steps):
        row = 0 if idx < 4 else 1
        col = idx if row == 0 else 7 - idx
        x = 0.5 + col * 2.3
        y = 3.6 if row == 0 else 1.2

        draw_box(ax, x, y, 2.1, 1.4, title, sub, bg="#FFFFFF", border=color, title_color=color, title_size=9.5, sub_size=7.8)

        # Draw connecting arrows
        if row == 0 and col < 3:
            draw_arrow(ax, x + 2.1, y + 0.7, x + 2.3, y + 0.7, color=color, lw=1.8)
        elif row == 0 and col == 3:
            # Turn down
            ax.annotate("", xy=(x + 1.05, 2.6), xytext=(x + 1.05, 3.6),
                        arrowprops=dict(arrowstyle="->,head_width=0.3,head_length=0.4", color="#64748B", lw=1.8))
        elif row == 1 and col > 0:
            draw_arrow(ax, x, y + 0.7, x - 0.2, y + 0.7, color=color, lw=1.8)

    return save_fig(fig, "fig2_scan_lifecycle.png")


# -------------------------------------------------------------
# Figure 3: FindingGate 8-Point Verification Pipeline
# -------------------------------------------------------------
def make_fig3_finding_gate():
    fig, ax = plt.subplots(figsize=(10, 5.8), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6.2)
    ax.axis("off")

    ax.text(5, 5.9, "FindingGate Universal 8-Point Verification Pipeline", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 5.6, "Eliminates false positives via evidence proof, timing baselines, and vendor validation", ha="center", va="center", fontsize=9.5, color="#64748B")

    # Start Candidate
    draw_box(ax, 0.4, 2.3, 1.6, 1.5, "Candidate\nFinding", "Emitted by\nSecurity Module", bg="#EFF6FF", border=COLOR_BLUE, title_color=COLOR_BLUE)

    checks = [
        ("Gate 1: Evidence", "Substantive Proof\nLength ≥ 16 bytes", 2.4, 3.8),
        ("Gate 2: Syntax Escape", "Character Injection\nEscape Proof Valid", 4.3, 3.8),
        ("Gate 3: Vendor Regex", "Exact DB / Parser\nSignature Match", 6.2, 3.8),
        ("Gate 4: Timing Baseline", "3-Sample Stat Check\nΔ ≥ μ + 3σ", 8.1, 3.8),
        ("Gate 5: WAF Rejection", "Block Page Detection\nDrop False Positives", 8.1, 1.2),
        ("Gate 6: Diff Baseline", "Soft-404 / Catch-all\nDifferential Check", 6.2, 1.2),
        ("Gate 7: Platform Baseline", "Known-Platform Rules\nCloudflare, AWS, etc.", 4.3, 1.2),
        ("Gate 8: Severity Cap", "Bound Unverified\nCandidate Severity", 2.4, 1.2),
    ]

    for title, desc, cx, cy in checks:
        draw_box(ax, cx, cy, 1.5, 1.3, title, desc, bg="#F8FAFC", border="#64748B", title_size=8.5, sub_size=7.2)

    # Connections
    draw_arrow(ax, 2.0, 3.05, 2.4, 4.45, color=COLOR_BLUE)
    draw_arrow(ax, 3.9, 4.45, 4.3, 4.45, color=COLOR_GREEN)
    draw_arrow(ax, 5.8, 4.45, 6.2, 4.45, color=COLOR_GREEN)
    draw_arrow(ax, 7.7, 4.45, 8.1, 4.45, color=COLOR_GREEN)
    draw_arrow(ax, 8.85, 3.8, 8.85, 2.5, color=COLOR_GREEN)
    draw_arrow(ax, 8.1, 1.85, 7.7, 1.85, color=COLOR_GREEN)
    draw_arrow(ax, 6.2, 1.85, 5.8, 1.85, color=COLOR_GREEN)
    draw_arrow(ax, 4.3, 1.85, 3.9, 1.85, color=COLOR_GREEN)

    # End Result Box
    draw_box(ax, 0.4, 0.5, 1.6, 1.4, "Confirmed\nFinding", "Passed into\nReport & DB", bg="#ECFDF5", border=COLOR_GREEN, title_color=COLOR_GREEN)
    draw_arrow(ax, 2.4, 1.85, 2.0, 1.2, color=COLOR_GREEN)

    # Rejected finding annotation
    ax.text(5.2, 0.3, "✕ Failed checks are tagged with audit rejection reason and suppressed from reports", ha="center", va="center", fontsize=8.5, color=COLOR_RED, style="italic")

    return save_fig(fig, "fig3_finding_gate.png")


# -------------------------------------------------------------
# Figure 4: Vulnerability Chaining & Attack Path Builder
# -------------------------------------------------------------
def make_fig4_vuln_chain():
    fig, ax = plt.subplots(figsize=(10, 5.2), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.5)
    ax.axis("off")

    ax.text(5, 5.2, "Compound Vulnerability Chaining & Attack Path Synthesis", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 4.9, "Automated correlation of individual low/medium findings into critical multi-step exploits", ha="center", va="center", fontsize=9.5, color="#64748B")

    # Step 1: Initial Discovery
    draw_box(ax, 0.5, 2.6, 2.6, 1.5, "1. Initial Access", "SSRF Vulnerability\non Query Parameter\nSeverity: Medium", bg="#FEF3C7", border=COLOR_AMBER, title_color=COLOR_AMBER)

    # Step 2: Internal Pivot
    draw_box(ax, 3.7, 2.6, 2.6, 1.5, "2. Cloud Pivot", "Target Cloud Metadata\n169.254.169.254/latest\nSeverity: High", bg="#FFEDD5", border=COLOR_AMBER, title_color=COLOR_AMBER)
    draw_arrow(ax, 3.1, 3.35, 3.7, 3.35, color=COLOR_AMBER, text="Pivot", lw=2.0)

    # Step 3: Privilege Escalation
    draw_box(ax, 6.9, 2.6, 2.6, 1.5, "3. Credential Theft", "Extract Temporary IAM\nRole Tokens & Keys\nSeverity: High", bg="#FEE2E2", border=COLOR_RED, title_color=COLOR_RED)
    draw_arrow(ax, 6.3, 3.35, 6.9, 3.35, color=COLOR_RED, text="Exfiltrate", lw=2.0)

    # Step 4: Final Impact Chain
    draw_box(ax, 2.0, 0.5, 6.0, 1.3, "Compound Attack Chain: Full Cloud / BaaS Infrastructure Takeover", "Impact: SSRF + Cloud Metadata + IAM Key Exfiltration = Critical Infrastructure Compromise\nAutomated Risk Deduction: +35 Severity Upgrade (Critical)", bg="#EFF6FF", border=COLOR_BLUE, title_color=COLOR_NAVY_DARK)
    draw_arrow(ax, 8.2, 2.6, 7.0, 1.8, color=COLOR_RED, lw=2.0)

    return save_fig(fig, "fig4_vuln_chain.png")


# -------------------------------------------------------------
# Figure 5: Dependency DAG Execution Stages
# -------------------------------------------------------------
def make_fig5_dag_pipeline():
    fig, ax = plt.subplots(figsize=(10, 5.0), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.2)
    ax.axis("off")

    ax.text(5, 4.9, "PhantomScan Pipeline DAG Stratified Execution Stages", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 4.6, "Topologically scheduled parallel execution stages with dependency barrier synchronization", ha="center", va="center", fontsize=9.5, color="#64748B")

    stages = [
        ("Stage 0", "Scope & Health\nTargets & Checks", 0.3, COLOR_BLUE),
        ("Stage 1", "Reconnaissance\nDNS & Subdomains", 1.9, COLOR_TEAL),
        ("Stage 2", "Native Ports\nGo Port & Rust TLS", 3.5, COLOR_GREEN),
        ("Stage 3", "Crawl & Graph\nSpider & Tech Fingerprint", 5.1, COLOR_PURPLE),
        ("Stage 4", "Active AppSec\n38+ Modules Parallel", 6.7, COLOR_RED),
        ("Stage 5", "Verification\nFindingGate & PostProcess", 8.3, COLOR_NAVY_MED),
    ]

    for title, desc, cx, color in stages:
        draw_box(ax, cx, 1.8, 1.4, 2.0, title, desc, bg="#FFFFFF", border=color, title_color=color, title_size=10, sub_size=8)
        if cx < 8.0:
            draw_arrow(ax, cx + 1.4, 2.8, cx + 1.9, 2.8, color=color, lw=1.8)

    # Barrier sync label
    draw_box(ax, 1.0, 0.4, 8.0, 0.8, "Asynchronous Barrier Synchronization & Tech-Aware Pruning", "Modules are pruned if prerequisite technologies (e.g. GraphQL, Supabase, PHP) are absent from Asset Graph", bg="#F8FAFC", border="#94A3B8", title_size=9, sub_size=8)

    return save_fig(fig, "fig5_dag_pipeline.png")


# -------------------------------------------------------------
# Figure 6: Multi-Signal Technology Fingerprinting
# -------------------------------------------------------------
def make_fig6_tech_fingerprinting():
    fig, ax = plt.subplots(figsize=(10, 5.2), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.4)
    ax.axis("off")

    ax.text(5, 5.1, "Multi-Signal Technology Fingerprinting Architecture", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 4.8, "Four independent response observation channels synthesize the target Asset Graph", ha="center", va="center", fontsize=9.5, color="#64748B")

    # 4 Input Signals
    draw_box(ax, 0.5, 3.4, 2.0, 1.0, "HTTP Headers", "Server, X-Powered-By\nVia, X-AspNet-Version", bg="#EFF6FF", border=COLOR_BLUE)
    draw_box(ax, 2.8, 3.4, 2.0, 1.0, "Cookies & Flags", "PHPSESSID, connect.sid\nJSESSIONID, __cf_bm", bg="#F5F3FF", border=COLOR_PURPLE)
    draw_box(ax, 5.1, 3.4, 2.0, 1.0, "HTML & DOM", "meta generator, Next.js\n<script> bundle assets", bg="#F0FDF4", border=COLOR_GREEN)
    draw_box(ax, 7.4, 3.4, 2.0, 1.0, "Favicon Hashes", "MD5 & MurmurHash3\nFramework Signatures", bg="#FEF3C7", border=COLOR_AMBER)

    # Aggregator
    draw_box(ax, 2.5, 1.8, 5.0, 1.0, "detect_technologies() Synthesis Engine", "Pattern Matching • Version Extraction • Confidence Scoring", bg="#FFFFFF", border=COLOR_NAVY_MED, title_color=COLOR_NAVY_DARK)

    draw_arrow(ax, 1.5, 3.4, 3.5, 2.8, color=COLOR_BLUE)
    draw_arrow(ax, 3.8, 3.4, 4.5, 2.8, color=COLOR_PURPLE)
    draw_arrow(ax, 6.1, 3.4, 5.5, 2.8, color=COLOR_GREEN)
    draw_arrow(ax, 8.4, 3.4, 6.5, 2.8, color=COLOR_AMBER)

    # Output: Asset Graph
    draw_box(ax, 1.5, 0.3, 7.0, 0.9, "Target Asset Graph Model", "Enables Technology-Aware DAG Pruning (e.g. skips GraphQL tests if no GraphQL endpoint detected)", bg="#ECFDF5", border=COLOR_TEAL, title_color=COLOR_TEAL)
    draw_arrow(ax, 5.0, 1.8, 5.0, 1.2, color=COLOR_TEAL, lw=2.0)

    return save_fig(fig, "fig6_tech_fingerprinting.png")


# -------------------------------------------------------------
# Figure 7: Scope Normalization & Policy Enforcement
# -------------------------------------------------------------
def make_fig7_scope_normalization():
    fig, ax = plt.subplots(figsize=(10, 4.8), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.0)
    ax.axis("off")

    ax.text(5, 4.7, "Target Normalization & Scope Policy Decision Flow", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 4.4, "Multi-stage URL/host parsing, loopback isolation, and eTLD+1 scope bounding", ha="center", va="center", fontsize=9.5, color="#64748B")

    draw_box(ax, 0.4, 2.0, 1.8, 1.3, "Raw User Input", "example.com\n192.168.1.5:8080\nhttp://localhost:3000", bg="#EFF6FF", border=COLOR_BLUE)
    draw_box(ax, 2.6, 2.0, 2.0, 1.3, "Scheme Resolution", "Has scheme? Keep\nNo scheme: is local?\nLocal->HTTP, Pub->HTTPS", bg="#F8FAFC", border=COLOR_PURPLE)
    draw_box(ax, 5.0, 2.0, 2.1, 1.3, "Host & Port Parsing", "ipaddress.ip_address\ntldextract eTLD+1\nDefault Port 80/443", bg="#F8FAFC", border=COLOR_AMBER)
    draw_box(ax, 7.5, 2.0, 2.1, 1.3, "NormalizedTarget", "Immutable Dataclass\nis_local, web_root\nScope Boundary Set", bg="#ECFDF5", border=COLOR_GREEN, title_color=COLOR_GREEN)

    draw_arrow(ax, 2.2, 2.65, 2.6, 2.65, color=COLOR_BLUE)
    draw_arrow(ax, 4.6, 2.65, 5.0, 2.65, color=COLOR_PURPLE)
    draw_arrow(ax, 7.1, 2.65, 7.5, 2.65, color=COLOR_AMBER)

    draw_box(ax, 1.5, 0.4, 7.0, 0.9, "Strict Out-of-Scope Isolation Policy (PR-L01)", "Local/Private targets automatically skip public DNS/WHOIS/Subdomain Takeover checks.\nScans are strictly bounded to target host; external redirect jumps are rejected.", bg="#F1F5F9", border="#94A3B8", title_size=9, sub_size=8)

    return save_fig(fig, "fig7_scope_normalization.png")


# -------------------------------------------------------------
# Figure 8: Structured Evidence System Hierarchy
# -------------------------------------------------------------
def make_fig8_evidence_model():
    fig, ax = plt.subplots(figsize=(10, 5.2), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.4)
    ax.axis("off")

    ax.text(5, 5.1, "Structured Evidence System Typed Hierarchy", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 4.8, "Every finding enforces typed, verifiable technical proof for FindingGate validation", ha="center", va="center", fontsize=9.5, color="#64748B")

    # Base Evidence
    draw_box(ax, 3.2, 3.5, 3.6, 1.1, "Base Evidence (Dataclass)", "summary: str • verified: bool\nconfidence: float • timestamp: str", bg="#EFF6FF", border=COLOR_BLUE, title_color=COLOR_NAVY_DARK)

    # 4 Subclasses
    subclasses = [
        ("HTTPEvidence", "request_method, url\nrequest_headers, body\nresponse_status, snippet", 0.3, COLOR_TEAL),
        ("TimingEvidence", "baseline_mean (μ)\nbaseline_std (σ)\nmeasured_delay (Δ)", 2.8, COLOR_PURPLE),
        ("DOMEvidence", "sink, source\ntaint_path, context\nexecution_result", 5.3, COLOR_AMBER),
        ("ChainEvidence", "chain_id, steps\nintermediate_findings\ncompound_impact", 7.8, COLOR_RED),
    ]

    for title, desc, cx, color in subclasses:
        draw_box(ax, cx, 1.2, 2.0, 1.4, title, desc, bg="#FFFFFF", border=color, title_color=color, title_size=9, sub_size=7.5)
        draw_arrow(ax, 5.0, 3.5, cx + 1.0, 2.6, color="#64748B", lw=1.2)

    draw_box(ax, 1.0, 0.2, 8.0, 0.7, "Universal FindingGate Rule", "FindingGate rejects any finding where evidence length < 16 bytes or required subtype attributes are empty.", bg="#F8FAFC", border="#94A3B8", title_size=8.5, sub_size=7.5)

    return save_fig(fig, "fig8_evidence_model.png")


# -------------------------------------------------------------
# Figure 9: Finding Lifecycle State Machine
# -------------------------------------------------------------
def make_fig9_finding_lifecycle():
    fig, ax = plt.subplots(figsize=(10, 4.6), facecolor=BG_COLOR)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4.8)
    ax.axis("off")

    ax.text(5, 4.5, "Finding Lifecycle State Transitions & Fingerprinting", ha="center", va="center", fontsize=14, fontweight="bold", color=COLOR_NAVY_DARK)
    ax.text(5, 4.2, "Deterministic state progression with SHA-256 fingerprinting and audit trail logging", ha="center", va="center", fontsize=9.5, color="#64748B")

    # Linear States
    states = [
        ("Discovered", "Initial observation\nby raw analyzer", 0.5, COLOR_BLUE),
        ("Candidate", "Enriched with\nendpoint & parameter", 2.8, COLOR_PURPLE),
        ("Verifying", "Active probe proof\nor timing check", 5.1, COLOR_AMBER),
        ("Confirmed", "Passed FindingGate\nAssigned SHA-256", 7.4, COLOR_GREEN),
    ]

    for title, desc, cx, color in states:
        draw_box(ax, cx, 2.2, 2.0, 1.3, title, desc, bg="#FFFFFF", border=color, title_color=color, title_size=10, sub_size=8)
        if cx < 7.0:
            draw_arrow(ax, cx + 2.0, 2.85, cx + 2.3, 2.85, color=color, lw=1.8)

    # Suppressed / False Positive branch below
    draw_box(ax, 5.1, 0.4, 2.0, 1.2, "Suppressed", "Rejected by gate\nor platform baseline", bg="#FEF2F2", border=COLOR_RED, title_color=COLOR_RED, title_size=9.5, sub_size=7.5)
    draw_box(ax, 7.4, 0.4, 2.0, 1.2, "False Positive", "Logged to fp_log.json\nAudit trail stored", bg="#F8FAFC", border="#64748B", title_size=9.5, sub_size=7.5)

    draw_arrow(ax, 6.1, 2.2, 6.1, 1.6, color=COLOR_RED, text="Failed Proof", lw=1.5)
    draw_arrow(ax, 7.1, 1.0, 7.4, 1.0, color="#64748B", text="Log", lw=1.5)

    return save_fig(fig, "fig9_finding_lifecycle.png")


if __name__ == "__main__":
    print("Generating report diagram figures...")
    make_fig1_architecture()
    make_fig2_scan_lifecycle()
    make_fig3_finding_gate()
    make_fig4_vuln_chain()
    make_fig5_dag_pipeline()
    make_fig6_tech_fingerprinting()
    make_fig7_scope_normalization()
    make_fig8_evidence_model()
    make_fig9_finding_lifecycle()
    print("All diagrams generated successfully in docs/diagrams/!")


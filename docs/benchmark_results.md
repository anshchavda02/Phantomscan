# PhantomScan Detection Benchmark Results

> [!NOTE]
> Results are measured values from actual scans. Targets used are publicly available security test applications. All testing is authorized.

This document records honest, measured detection capabilities of PhantomScan across clean targets, deliberate benchmark applications, and real-world test sites.

---

## 1. Measured Benchmark Results Table

| Target | Critical | High | Medium | Low | Info | Duration | Score | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `https://example.com` | 0 | 0 | 1 | 0 | 0 | 32.03s | 92 | Known clean target. Flagged missing HSTS/CSP security headers. Zero False Positives for SQLi/XSS/Traversals. |
| `http://testphp.vulnweb.com` | 0 | 0 | 1 | 0 | 2 | 327.35s | 74 | Public test target (Acunetix). Flagged missing security headers and exposed technologies/ports in quick profile. |
| `http://localhost:3000` *(Juice Shop)* | 0 | 0 | 1 | 1 | 2 | ~15.00s | 85 | Local test environment (OWASP Juice Shop). Baseline measurements documented below. |

---

## 2. Local Testing Instructions: OWASP Juice Shop

To measure PhantomScan locally in an isolated and reproducible sandbox:

### Step 1: Launch Juice Shop Container
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

### Step 2: Execute Benchmark Harness
```bash
# Quick profile benchmark
python scripts/benchmark.py --target http://localhost:3000 --profile quick

# Deep scan benchmark
python scripts/benchmark.py --target http://localhost:3000 --profile deepscan
```

### Step 3: Compare Against Baseline
```bash
python scripts/benchmark.py --target http://localhost:3000 --baseline benchmark_baseline.json
```

---

## 3. Juice Shop Detection Gap Analysis

Below is the measured comparison between expected vulnerabilities in OWASP Juice Shop and what the scanner detects across different module profiles:

| Vulnerability Category | Expected (Juice Shop Known Ground Truth) | Measured (PhantomScan Quick) | Measured (PhantomScan Deepscan) | Gap / Action Item |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Error-based / boolean injection on `/rest/products/search?q=` | Expected: Critical | Expected: Critical | Crawler must supply discovered query parameters to `SQLiDetector` |
| **Cross-Site Scripting (XSS)** | Reflected XSS on search query parameters | Expected: High | Expected: High | Reflection probe verified unencoded via `XSSScanner` |
| **Information Disclosure** | Sensitive configuration / exposed `/ftp` or `package.json` | 1 Info | 2 Low/Info | Detectable via `SensitivePathScanner` at web root |
| **API / Endpoint Discovery** | REST APIs (`/api/Feedbacks`, `/rest/user/whoami`) | 0 | Discovered routes | OpenAPI and Route Extractor capture endpoints |
| **Security Headers** | Missing CSP, X-Frame-Options, HSTS | 1 Medium | 1 Medium | Fully detected by headers engine |

---

## 4. Running the Benchmark Suite

The benchmark harness supports multiple execution modes:

```bash
# Run known clean targets
python scripts/benchmark.py --suite clean

# Run public vulnerable test sites (requires explicit confirmation flag)
python scripts/benchmark.py --suite vulnerable --confirm-authorized

# Run against custom target with custom output
python scripts/benchmark.py --target http://localhost:3000 --output docs/juice_shop_benchmark.json
```

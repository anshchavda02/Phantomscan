# Verification Examples

## google.com Expected Shape

- Score: high, commonly A range when only passive findings are considered.
- Critical: 0
- High: 0
- WAF/CDN: contextual known-platform observation for Google.
- Email: root-domain context is used instead of `www`.

## rayinfra.in Expected Shape

- Score: depends on observed headers, exposed ports, and direct evidence.
- CVEs: suppressed unless exact product/version evidence exists.
- Report: HTML and JSON are generated under `reports/`.

## Dependency Status Table

| Dependency | Required | Behavior if missing |
| --- | --- | --- |
| Python | yes | CLI cannot run |
| Go engine | no | skipped with warning |
| Rust engine | no | skipped with warning |
| Node | no | browser engine skipped with warning |
| nmap | no | wrapper exits 2 |

## Sample HTML Section

```html
<section class="grid">
  <div class="tile"><div>Score</div><div class="score">92</div></div>
  <div class="tile"><div>Grade</div><div class="score">A</div></div>
</section>
```


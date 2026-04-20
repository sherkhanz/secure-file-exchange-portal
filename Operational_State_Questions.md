# Operational State Questions: Secure File Exchange Portal

---

## System Health

- Is the API currently up and accepting requests?
- How many files have been uploaded in total?
- Is the container running and healthy?

---

## Security & Threat Detection

- Are we actively under a token enumeration attack right now?
- How many failed download attempts have occurred - is this number spiking?
- Are there unauthorized API requests indicating credential brute-force?
- Has anyone attempted to use a revoked or expired token?
- Were any suspicious file types (`.php`, `.sh`, `.exe`) uploaded?
- How many successful downloads happened - does this correlate with known activity?

---

## Link Lifecycle

- How many download links are currently active and valid?
- How many links have been manually revoked?
- What files were uploaded most recently - do they look legitimate?

---

## Storage & Capacity

- Are we approaching the 20 MB storage hard cap?
- How much total disk space are uploaded files consuming right now?
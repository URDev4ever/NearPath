<h1 align="center">NearPath</h1>

<h2 align="center">Guided Surface Fuzzer & Content Discovery Engine</h2>

<h3 align="center">NearPath is a lightweight, guided fuzzing tool designed to discover hidden web application endpoints by combining shallow crawling, JavaScript mining, and heuristic path mutation.
It does not brute-force large wordlists. Instead, it expands what the application already reveals and intelligently probes what likely exists.</h3>

---
This makes NearPath ideal for:

* API surface mapping
* Hidden route discovery
* Internal endpoint exposure analysis
* Forgotten / legacy path detection

---

## Philosophy

NearPath is not a spider.
NearPath is not a brute-force fuzzer.

NearPath answers one specific question:

> **“What probably exists here that the site does not link to?”**

It does this by:

1. Observing real routes from HTML and JavaScript
2. Extracting structural hints
3. Generating intelligent mutations
4. Validating them using response fingerprinting

This allows NearPath to find endpoints that normal crawlers and directory fuzzers miss.

---

## Core Features

### Guided Path Discovery

NearPath extracts URLs from:

* HTML (`href`, `src`, `action`)
* JavaScript (`fetch`, `import`, `require`, quoted paths)

These real paths become **seeds** for further expansion.

---

### Heuristic Mutation Engine

Discovered paths are mutated using structural rules:

* `_old`, `_bak`, `_dev`, `_test`
* `.json`, `.php`, `.xml`, `.txt`
* `/v1`, `/v2`, `/internal`, `/private`
* pluralization & truncation
* API version pivoting

This creates high-quality guesses instead of noisy brute force. WAY faster

---

### Fake-404 Detection

Modern apps often return HTTP 200 for missing pages (SPA fallback routes).

NearPath fingerprints:

* Status code
* Response length
* Headers

This allows it to distinguish:

```
Real endpoints vs Fake pages
```

Even when everything returns 200. **Say goodbye to false positives**

---

### JavaScript-Driven Discovery

NearPath parses JavaScript files and extracts:

* Fetch calls
* Imports
* Quoted API paths

This reveals backend routes that never appear in HTML.

---

### Priority-Based Scanning

Paths are scored by how they were discovered:

* Direct links = high priority
* JS references = higher priority
* Mutations = lower priority

This ensures:

* Real surfaces are scanned first
* Noise is naturally limited

---

### Multi-Threaded & Interrupt-Safe

NearPath supports:

* Concurrent workers
* Ctrl+C safe shutdown
* Graceful stop with full result persistence

---

### Structured Output

Each target gets its own folder:

```
nearpath_results/
└── example.com/
    ├── discovered.txt
    ├── target.json
    ├── responses.db
    └── js_sources.txt
```

---

## Installation

Clone the repository and go to it's directory:

```bash
git clone https://github.com/URDev4ever/NearPath.git
cd NearPath/
```

```bash
pip install requests
```

Python 3.8+ required.

---

## Usage

```bash
python nearpath.py
```

NearPath runs in interactive mode:

```
Target URL:
Max depth (default 2):
Timeout per request (default 6):
Follow JS imports? (Y/n):
Max mutations per path (default 12):
```

No flags are required.
Everything is configured through prompts. (btw you can just 'enter' to keep default)

---

## How NearPath Works

```
Target URL
   ↓
HTML crawl
   ↓
JS extraction
   ↓
Path collection
   ↓
Mutation engine
   ↓
Fake-404 filtering
   ↓
Priority queue
   ↓
Validated endpoints
   ↓
Database + reports
```

NearPath does not try everything.
It tries **what makes sense**, that's why is **10x faster** than your normal fuzzer.

---

## Output Files

### `discovered.txt`

Human-readable list of endpoints:

```
https://site/api/users - 200 - 1345b
https://site/api/internal - 403 - 421b
```

---

### `target.json`

Structured scan data grouped by base path:

```json
{
  "/api/users": {
    "https://site/api/users": {
      "status": 200,
      "length": 1345,
      "type": "application/json",
      "priority": 7
    }
  }
}
```

---

### `responses.db`

SQLite database containing:

* URL
* Path
* Status
* Length
* Headers
* Timestamp

This allows later analysis, filtering, and correlation.

---

### `js_sources.txt`

Captured JavaScript snippets that were mined for endpoints.

This is useful for:

* Manual review
* API reverse engineering
* Diffing versions

---

## What NearPath Is Not

NearPath does **not**:

* Run payloads
* Inject data
* Test vulnerabilities
* Guess large wordlists
* Perform authentication attacks

It strictly maps and validates **surface area**.

---

## When to Use NearPath

Use NearPath when:

* You want to understand a web application's real API
* You want to find undocumented endpoints
* You want to discover forgotten or legacy routes
* You want to map what exists before deeper testing

---

## Performance Profile

NearPath is intentionally “chill fuzzing”:

* Low noise
* Low bandwidth
* High signal

It scales based on:

* Depth
* Mutation count
* Thread count

---

## Caution

NearPath is provided as-is for research, auditing, and defensive analysis.

Use only against systems you own or are authorized to test.

---
Made with <3 by URDev.

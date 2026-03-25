# IOC Dashboard

A web-based **Threat Intelligence dashboard** for Security Operations Center (SOC) analysts. Upload threat reports, automatically extract and enrich IP Indicators of Compromise (IoCs) via VirusTotal, and store the results as MISP events — all from a single interface.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Scoring Logic](#scoring-logic)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)

---

## Overview

IOC Dashboard automates the SOC analyst workflow for processing threat reports:

```
Upload .txt report → vt_tools.py extracts IPs → VirusTotal enrichment
   → CSV results → MISP event created → Dashboard displays results
```

MISP is the **single source of truth** — the dashboard always reads back from MISP after writing, never from intermediate CSV files.

---

## Features

- **File Upload** — Drag-and-drop or click-to-upload `.txt` threat reports
- **Automated Pipeline** — Triggers `vt_tools.py` to extract IPs and query VirusTotal
- **MISP Integration** — Creates MISP events with enriched IoC attributes; reads back results from MISP
- **Threat Scoring** — Classifies each IP as `MALICIOUS`, `SUSPECT`, `CLEAN`, or `UNKNOWN` based on VirusTotal detection count
- **KPI Summary** — Displays counts of malicious, suspicious, clean, and unknown IPs per analysis
- **Analysis History** — Browse all past MISP events with search and filtering
- **CSV Export** — Download analysis results as a CSV file
- **Manual MISP Events** — Create MISP events manually by pasting IoCs directly into the UI
- **Session API Key Management** — Provide VirusTotal and MISP keys in-browser; keys are never written to disk
- **TLP Classification** — Set Traffic Light Protocol level (`WHITE`, `GREEN`, `AMBER`, `RED`) per event
- **Proxy Support** — Optional HTTP/HTTPS proxy for VirusTotal API calls

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 Browser (UI)                    │
│  index.html · results.html · history.html       │
└───────────────────┬─────────────────────────────┘
                    │ HTTP (Flask)
┌───────────────────▼─────────────────────────────┐
│              app.py  (Flask)                    │
│                                                 │
│  /           → index()      list MISP events    │
│  /analyze    → analyze()    run pipeline        │
│  /history    → history()    browse events       │
└──────┬─────────────────────────┬────────────────┘
       │                         │
┌──────▼──────┐         ┌────────▼────────┐
│  vt_tools.py│         │   MISP Server   │
│  (external) │         │   (PyMISP)      │
│             │         │                 │
│  Reads .txt │         │  - add_event()  │
│  Queries VT │         │  - get_event()  │
│  Writes CSV │         │  - search()     │
└──────┬──────┘         └─────────────────┘
       │ Results/
┌──────▼──────┐
│  *_IP_      │
│  Analysis_  │
│  *.csv      │
└─────────────┘
```

**Key design principle:** `vt_tools.py` writes a CSV; `app.py` parses it once to push data into MISP, then discards the CSV — all subsequent reads come from MISP.

---

## Scoring Logic

Each IP address is classified based on the number of VirusTotal malicious detections:

| Detections       | Status      | Badge colour |
|------------------|-------------|--------------|
| > 5 engines      | `MALICIOUS` | 🔴 Red       |
| 1 – 5 engines    | `SUSPECT`   | 🟠 Orange    |
| 0 engines        | `CLEAN`     | 🟢 Green     |
| Score not found  | `UNKNOWN`   | ⚫ Grey      |

---

## Requirements

### System

| Requirement | Version |
|-------------|---------|
| Python      | ≥ 3.9   |
| pip         | latest  |

### Python packages

| Package   | Purpose                               |
|-----------|---------------------------------------|
| `flask`   | Web framework                         |
| `pymisp`  | MISP REST API client                  |

Install them with:

```bash
pip install flask pymisp
```

### External services

| Service               | Required | Notes |
|-----------------------|----------|-------|
| **MISP instance**     | Yes      | Reachable from the host running `app.py`; an API key with event-write access is required |
| **VirusTotal API key**| Yes      | Free or commercial key; passed via environment variable or the in-browser settings panel |

### External script — `vt_tools.py`

The analysis pipeline depends on an external script called `vt_tools.py` that must be present in `VT_TOOL_DIR` (default: `~/vt_tool/`).  
This script is **not included** in this repository — you must supply or create it separately and place it (along with a `Results/` subdirectory) inside `VT_TOOL_DIR`.

`vt_tools.py` is invoked by the dashboard as:

```bash
python vt_tools.py -n -f <report.txt>
```

It must:
1. Accept `-n` (non-interactive) and `-f <path>` (input file) flags
2. Read `VT_API_KEY` from the environment
3. Optionally read `HTTP_PROXY` / `HTTPS_PROXY` for proxy support
4. Write a CSV file matching the pattern `Results/*_IP_Analysis_*.csv` with at least the columns: `ip`, `malicious_score`, `total_scans`, `tags`, `link`

> If you do not have `vt_tools.py`, you can create a compatible script that queries the [VirusTotal Public API v3](https://developers.virustotal.com/reference/overview) for each IP address found in the input file and writes the results in the expected CSV format.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/IOC_Dashboard.git
cd IOC_Dashboard

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install flask pymisp

# 4. Ensure vt_tools.py is available (see VT_TOOL_DIR below)
```

---

## Configuration

All settings are controlled via **environment variables**:

| Variable        | Default              | Description |
|-----------------|----------------------|-------------|
| `MISPURL`       | `https://localhost`  | Base URL of your MISP instance |
| `MISPKEY`       | *(empty)*            | MISP user API key (required) |
| `MISPSSLVERIFY` | `False`              | Set to `True` or `1` to enable SSL certificate verification for MISP |
| `VT_TOOL_DIR`   | `~/vt_tool`          | Directory containing `vt_tools.py` and its `Results/` sub-folder |
| `VT_API_KEY`    | *(empty)*            | VirusTotal API key (can also be provided in-browser per session) |
| `HTTP_PROXY`    | *(empty)*            | HTTP proxy URL forwarded to `vt_tools.py` |
| `HTTPS_PROXY`   | *(empty)*            | HTTPS proxy URL forwarded to `vt_tools.py` |

Export them before starting the app, for example:

```bash
export MISPURL="https://misp.example.com"
export MISPKEY="your_misp_api_key_here"
export MISPSSLVERIFY="True"
export VT_TOOL_DIR="/opt/vt_tool"
export VT_API_KEY="your_virustotal_api_key_here"
```

> **Security note:** API keys provided in the browser settings panel are stored in JavaScript session memory only — they are never written to disk, cookies, or URL parameters.

---

## Running the Application

```bash
python app.py
```

The server starts on `http://0.0.0.0:5000`. Open your browser at `http://localhost:5000`.

Startup output:

```
[IOC Dashboard] VT_TOOL_DIR : /opt/vt_tool
[IOC Dashboard] MISP URL    : https://misp.example.com
[IOC Dashboard] MISP KEY    : OK
```

> For production deployments, run behind a WSGI server such as **Gunicorn** (`gunicorn app:app`) and a reverse proxy (nginx / Apache). Disable Flask debug mode by removing `debug=True` from `app.run()`.

---

## Usage

### 1 — Upload & Analyze

1. Open the dashboard at `http://localhost:5000`
2. If prompted, enter your VirusTotal API key in the modal (or skip to use the server's `VT_API_KEY` env var)
3. Drag and drop a `.txt` threat report onto the upload zone, or click to browse
4. Click **⚡ Run Analysis**
5. The dashboard runs the full pipeline and redirects to the Results page

### 2 — Results Page

- View a KPI summary (Malicious / Suspicious / Clean / Unknown counts)
- Filter or sort the IoC table by value or status
- Copy individual IP addresses to the clipboard
- Export the full result set as a CSV file
- Push results to a new MISP event directly from this page

### 3 — History

Navigate to `/history` (or click **History** in the nav bar) to browse all MISP events, search by title, and open any event directly in the MISP web UI.

### 4 — Manual MISP Event

In the **Settings & Controls** section on the home page, switch to the **Manual MISP Event** tab to create a MISP event by pasting IoCs (one per line) without uploading a file.

---

## Project Structure

```
IOC_Dashboard/
├── app.py               # Flask application — routes, MISP client, CSV parsing
├── templates/
│   ├── index.html       # Home page — upload form, recent analyses, settings
│   ├── results.html     # Analysis results page — KPI, IoC table, MISP export
│   └── history.html     # MISP event history browser
└── static/
    └── style.css        # Dark-theme stylesheet (CSS variables, responsive)
```

---

## Screenshots

> _Screenshots will appear here once the application is running._

| Page     | Description |
|----------|-------------|
| Home     | Upload form, recent MISP events, API configuration |
| Results  | KPI cards, filterable IoC table, CSV export |
| History  | Searchable list of all past MISP events |

# VulnWatch

VulnWatch produces a ranked, current vulnerability report for Windows, macOS,
Linux, Android, and iOS/iPadOS. It combines:

- NIST NVD CVE, CVSS, affected-platform, and advisory data
- CISA Known Exploited Vulnerabilities (KEV) and required remediation actions
- FIRST EPSS daily exploitation probability

It creates a searchable HTML dashboard plus machine-readable CSV and JSON.

## Run

Python 3.10 or newer is the only dependency.

### Desktop interface

On Windows, launch the themed GUI with:

```powershell
python .\vulnwatch_gui.py
```

The GUI provides scan settings, live activity, cancellation, remembered
preferences, timestamped report history, and one-click report opening. Reports
default to `Documents\VulnWatch\Reports`, regardless of the folder
from which Python was launched.

### Command line

```bash
python3 vulnwatch.py
```

Open `report/index.html` in a browser. The default is the top 100 across all five
platform groups published in the last 120 days.

Useful options:

```bash
# Up to 100 for each platform (the combined report can exceed 100)
python3 vulnwatch.py --per-platform --limit 100

# A wider publication window and a different destination
python3 vulnwatch.py --days 365 --output current-report

# NVD strongly recommends an API key for larger jobs
NVD_API_KEY="your-key" python3 vulnwatch.py --days 365
```

## Ranking

The risk score is capped at 100 and combines CVSS severity, EPSS probability,
CISA KEV status, known ransomware use, and publication recency. CISA KEV has the
largest single weight because it confirms exploitation in the wild. A high rank
does **not** prove a device is affected; installed product/version inventory must
still be compared with the vendor advisory.

## Meaning of “current”

“Current” means published within `--days` (120 by default), not “unpatched on
every device.” Vulnerability status depends on the installed version and patch
level. Remediation text is sourced from CISA when available. Otherwise VulnWatch
links the NVD-tagged vendor/patch advisory and recommends upgrading to a confirmed
fixed version; it never invents a patch number.

## Scheduling

Run daily with cron, Task Scheduler, or a CI job. Reports are replaced atomically
at the file level, making the output directory suitable for serving with any
static web server.

## Data-source notes

NVD rate limits are much lower without a free API key. A 120-day run is typically
several paginated requests; wider ranges can take minutes. Platform classification
uses NVD CPE applicability plus conservative description matching. Review unusual
cross-platform software manually before acting.

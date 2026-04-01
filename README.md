# 🔍 Bug Bounty Recon Scripts

> A collection of focused, practical recon scripts for bug bounty hunting.
> Each script does one thing well and chains with the others.

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)

---

## ⚠️ Legal Notice

**Only use these scripts on targets you have explicit written permission to test.**
Unauthorized use is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.
Always stay within the defined scope of the bug bounty program.

---

## 📁 Repository Structure

```
bug-bounty-recon-scripts/
├── scripts/
│   ├── 01_subdomain_enum.sh       # Subdomain discovery + alive check
│   ├── 02_js_analysis.py          # JS file extraction + secret hunting
│   ├── 03_api_discovery.sh        # API endpoint discovery
│   ├── 04_full_recon_pipeline.sh  # Full automated recon chain
│   └── 05_idor_param_finder.py    # IDOR-prone parameter finder
├── wordlists/
│   └── README.md                  # Where to get wordlists
├── output/                        # Script outputs go here (gitignored)
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

```bash
git clone https://github.com/Chetan-Biranje/bug-bounty-recon-scripts.git
cd bug-bounty-recon-scripts
pip install -r requirements.txt
chmod +x scripts/*.sh

# Run full pipeline against a target
./scripts/04_full_recon_pipeline.sh target.com
```

---

## 🛠️ Dependencies

**Install all at once:**
```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/gf@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python
pip install -r requirements.txt

# System
sudo apt install nmap curl jq -y
```

---

## 📜 Scripts Overview

| Script | What It Does | Input | Output |
|---|---|---|---|
| `01_subdomain_enum.sh` | Finds + probes subdomains | domain | `alive_subs.txt` |
| `02_js_analysis.py` | Extracts endpoints + secrets from JS | domain/URL file | `js_findings.txt` |
| `03_api_discovery.sh` | Discovers API endpoints | domain | `api_endpoints.txt` |
| `04_full_recon_pipeline.sh` | Chains all scripts | domain | Full report folder |
| `05_idor_param_finder.py` | Finds numeric/ID params | URL file | `idor_candidates.txt` |

---

## 📄 License

MIT — see [LICENSE](LICENSE)

*Built by [Chetan Biranje](https://github.com/Chetan-Biranje) · AppSec Engineer · Bug Hunter*

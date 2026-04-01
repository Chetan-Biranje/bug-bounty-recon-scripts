# 🛡️ Threat Modeling Notes

> Personal threat modeling reference — STRIDE framework, templates, real-world examples, and checklists for AppSec engineers and bug hunters.

![AppSec](https://img.shields.io/badge/AppSec-Threat%20Modeling-blue?style=flat)
![Framework](https://img.shields.io/badge/Framework-STRIDE-red?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## 📁 Structure

```
threat-modeling-notes/
├── README.md
├── 01_stride_framework.md        # STRIDE theory + quick reference
├── 02_templates/
│   ├── web_app_template.md       # Threat model template for web apps
│   ├── api_template.md           # Threat model template for REST APIs
│   └── login_flow_template.md    # Threat model template for login/auth
├── 03_examples/
│   ├── login_flow_example.md     # Worked example — login system
│   ├── rest_api_example.md       # Worked example — REST API
│   └── file_upload_example.md    # Worked example — file upload feature
├── 04_checklists/
│   ├── web_app_checklist.md      # Security checklist for web apps
│   ├── api_checklist.md          # Security checklist for APIs
│   └── auth_checklist.md        # Security checklist for authentication
└── 05_resources.md               # Books, tools, references
```

---

## ⚡ Quick Reference — STRIDE

| Letter | Threat | Question to ask | Example |
|---|---|---|---|
| **S** | Spoofing | Can someone pretend to be someone else? | Login as another user |
| **T** | Tampering | Can data be modified in transit or storage? | Modify request body |
| **R** | Repudiation | Can someone deny doing an action? | No audit logs |
| **I** | Info Disclosure | Can sensitive data be leaked? | Error messages expose stack traces |
| **D** | Denial of Service | Can availability be disrupted? | No rate limiting on login |
| **E** | Elevation of Privilege | Can someone gain more access than allowed? | Regular user hits admin endpoint |

---

## 🔧 Tools

| Tool | Use | Link |
|---|---|---|
| OWASP Threat Dragon | Free, browser-based DFD + threat modeling | [threatdragon.github.io](https://threatdragon.github.io/) |
| Microsoft Threat Modeling Tool | Windows app, STRIDE-focused | [Download](https://aka.ms/tmt) |
| draw.io | Free DFD diagrams | [draw.io](https://draw.io) |
| Excalidraw | Quick whiteboard-style DFDs | [excalidraw.com](https://excalidraw.com) |

---

*Built by [Chetan Biranje](https://github.com/Chetan-Biranje) · AppSec Engineer*

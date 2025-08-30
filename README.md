# OSS Compliance & SBOM Scanner – UI

⚙️ **OSS Compliance & SBOM Scanner – Web Interface**  
🔒 For EY Internal Use Only  

This repository contains the **Streamlit-based user interface (UI)** for triggering **OSS compliance scans** remotely.  
The actual scanning and report generation are performed by the backend repo:  
👉 [Universal-OSS-Compliance](https://github.com/Bharathnelle335/Universal-OSS-Compliance)

---

## 🚀 What This UI Does
- Provides a **full-screen web UI** for initiating scans.  
- Lets you choose **scan type** (Docker image or Git repo).  
- Lets you select **scanners**:
  - ✅ **Syft** – Generate Software Bill of Materials (SBOM)  
  - ✅ **Grype** – Detect vulnerabilities in packages & images  
  - ✅ **SCANOSS** – Identify OSS licenses & components  
- Prevents duplicate scan requests within **3 minutes** for the same input.  
- Tracks **scan history (last 5 runs)** with timestamp, user, and settings.  
- Provides a **direct GitHub Actions link** to view/download reports.  

⚠️ **Note:** This repo does **not** contain scanning logic. It only triggers the backend workflow.

---
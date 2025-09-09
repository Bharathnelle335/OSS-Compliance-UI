import re
import streamlit as st
import requests
import time
from datetime import datetime
import pandas as pd

# ---------------- CONFIG ---------------- #
OWNER = "Bharathnelle335"
REPO = "Universal-OSS-Compliance"
WORKFLOW_FILE = "oss-compliance.yml"   # Must match workflow filename in backend repo
BRANCH = "main"                        # Update if repo default branch is not main

TOKEN = st.secrets.get("GITHUB_TOKEN", "")

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json"
}

# ---------------- HELPERS ---------------- #
def normalize_github_url_and_ref(url: str, ref_input: str):
    """
    Returns (normalized_git_url, resolved_ref, meta)
    - Accepts web URLs like:
        https://github.com/<owner>/<repo>/tree/<ref>
        https://github.com/<owner>/<repo>/commit/<sha>
        https://github.com/<owner>/<repo>/releases/tag/<tag>
      and converts to https://github.com/<owner>/<repo>.git, extracting ref if present.
    - If ref_input is provided, it takes precedence (after stripping refs/heads|refs/tags).
    """
    url = (url or "").strip()
    ref_input = (ref_input or "").strip()

    # Clean "refs/heads/" or "refs/tags/" prefixes if user pasted full ref path
    ref_input = ref_input.replace("refs/heads/", "").replace("refs/tags/", "")

    base_url = url
    detected_ref = ""

    if url.startswith("https://github.com/"):
        if "/tree/" in url:
            detected_ref = url.split("/tree/", 1)[1].split("/", 1)[0]
            base_url = url.split("/tree/", 1)[0]
        elif "/commit/" in url:
            detected_ref = url.split("/commit/", 1)[1].split("/", 1)[0]
            base_url = url.split("/commit/", 1)[0]
        elif "/releases/tag/" in url:
            detected_ref = url.split("/releases/tag/", 1)[1].split("/", 1)[0]
            base_url = url.split("/releases/tag/", 1)[0]
        # ensure .git suffix for Git operations
        if not base_url.endswith(".git"):
            base_url = base_url.rstrip("/") + ".git"

    # Choose resolved ref: explicit > detected > ""
    resolved_ref = ref_input or detected_ref or ""

    meta = {
        "parsed_from_url": bool(detected_ref),
        "detected_ref": detected_ref,
        "normalized_url": base_url
    }
    return base_url, resolved_ref, meta

def trigger_workflow(scan_type, value, enable_syft, enable_grype, enable_scanoss, git_ref_input=""):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/workflows/{WORKFLOW_FILE}/dispatches"

    # Build inputs
    inputs = {
        "scan_type": scan_type,
        "docker_image": value if scan_type == "docker" else "",
        "git_url": "",
        "enable_syft": str(enable_syft).lower(),
        "enable_grype": str(enable_grype).lower(),
        "enable_scanoss": str(enable_scanoss).lower()
    }

    # Normalize Git inputs if scanning a repo
    if scan_type == "git":
        norm_url, resolved_ref, _ = normalize_github_url_and_ref(value, git_ref_input)
        inputs["git_url"] = norm_url
        # Only include git_ref if non-empty to avoid 422 when workflow doesn't define it
        if resolved_ref:
            inputs["git_ref"] = resolved_ref

    data = {"ref": BRANCH, "inputs": inputs}
    r = requests.post(url, headers=headers, json=data)
    return r.status_code == 204, r.text

def get_workflow_runs_url():
    return f"https://github.com/{OWNER}/{REPO}/actions"

# ---------------- UI CONFIG ---------------- #
st.set_page_config(page_title="OSS Compliance & SBOM Scanner", layout="wide")

# Global CSS (rectangle Start Scan like Results)
st.markdown(
    """
    <style>
    .block-container {padding-top: 0rem;}
    /* Style ALL Streamlit buttons (e.g., Start Scan) */
    div[data-testid="stButton"] > button {
        background-color: #28a745 !important;   /* green */
        color: white !important;
        font-weight: bold !important;
        border-radius: 6px !important;          /* rectangle with small rounding */
        height: 45px !important;
        padding: 10px 12px !important;
        font-size: 15px !important;
    }
    div[data-testid="stButton"] > button:hover {
        background-color: #218838 !important;
        color: white !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------- HEADER ---------------- #
st.markdown(
    """
    <div style="text-align:center; padding-top:30px; padding-bottom:5px;">
        <h2 style="margin-bottom:5px;">OSS Compliance & SBOM Scanner</h2>
        <p style="color:#b30000; font-weight:500; margin-top:0; font-size:14px;">
            For EY Internal Use Only
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# ---------------- MAIN LAYOUT (2 COLUMNS) ---------------- #
left_col, right_col = st.columns([7, 3])

# ================= LEFT: SCAN SETTINGS ================= #
with left_col:
    if not TOKEN:
        st.warning("⚠️ No GitHub Token found. Please set `GITHUB_TOKEN` in `.streamlit/secrets.toml`")
    else:
        st.subheader("⚙️ Scan Settings")

        # --- Your Name ---
        user_name = st.text_input("Your Name", placeholder="Enter your name")

        # --- Select Scan Type ---
        scan_type = st.selectbox("Select Scan Type", ["docker", "git"], index=0)

        # --- Input Value ---
        value = st.text_input(
            "Input Value",
            placeholder="nginx:latest  OR  https://github.com/owner/repo[.git][/tree/v1.2.3]",
            help="For Git, you can paste a normal repo URL or a web URL containing /tree/<ref>, /commit/<sha>, or /releases/tag/<tag>."
        )

        # --- Optional Git ref (only shown for git) ---
        git_ref_input = ""
        if scan_type == "git":
            git_ref_input = st.text_input(
                "Git ref (branch / tag / commit) — optional",
                value="",
                help="Examples: main, v1.2.3, 1a2b3c4. Leave blank if your URL already includes /tree/<ref> or /releases/tag/<tag>."
            )

            # Live preview to build trust
            norm_url, resolved_ref, meta = normalize_github_url_and_ref(value, git_ref_input)
            with st.expander("🔎 Git input normalization preview", expanded=False):
                st.write("**Repo URL (normalized):**", norm_url or "(none)")
                st.write("**Ref (resolved):**", resolved_ref or "(none)")
                if meta.get("parsed_from_url"):
                    st.info(f"Detected ref `{meta.get('detected_ref')}` from the pasted URL.")

        # --- Select Scanners ---
        st.markdown("### 🛠️ Select Scanners")
        enable_syft = st.checkbox("Syft – Generate SBOM (Software Bill of Materials)", value=True)
        enable_grype = st.checkbox("Grype – Detect vulnerabilities in packages & images", value=True)
        enable_scanoss = st.checkbox("SCANOSS – Identify OSS licenses & components", value=True)

        # --- Password + Start Scan + Results in same row ---
        col1, col2, col3 = st.columns([2,1,1])  # Password 50%, Scan 25%, Results 25%
        with col1:
            password = st.text_input("Password", type="password", placeholder="Enter password")
        with col2:
            start_scan = st.button("🚀 Start Scan", use_container_width=True)
        with col3:
            workflow_url = get_workflow_runs_url()
            st.markdown(
                f"""
                <a href="{workflow_url}" target="_blank" style="
                    background-color:#007bff;
                    color:white;
                    padding:10px 12px;
                    border-radius:6px;
                    font-weight:bold;
                    text-decoration:none;
                    display:inline-block;
                    width:100%;
                    height:45px;
                    text-align:center;
                    line-height:25px;
                ">
                    🔗 Results
                </a>
                """,
                unsafe_allow_html=True
            )

        scan_allowed = password == "12345"

        # --- Session state for history/throttling ---
        if "last_trigger" not in st.session_state:
            st.session_state.last_trigger = {"scan_type": None, "value": None, "scanners": None, "timestamp": 0}
        if "scan_history" not in st.session_state:
            st.session_state.scan_history = []
        if "workflow_url" not in st.session_state:
            st.session_state.workflow_url = None

        # --- Scan Logic ---
        if start_scan:
            if not scan_allowed:
                st.error("❌ Invalid password. Access denied.")
            else:
                current_input = {
                    "scan_type": scan_type,
                    "value": value.strip(),
                    "git_ref": (git_ref_input or "").strip(),
                    "scanners": (enable_syft, enable_grype, enable_scanoss)
                }
                now = time.time()
                last = st.session_state.last_trigger

                if user_name.strip() == "":
                    st.error("⚠️ Please enter your name before triggering the scan.")
                elif current_input["value"] == "":
                    st.error("⚠️ Please provide an input value before starting the scan.")
                elif (current_input["scan_type"] == last["scan_type"] and
                      current_input["value"] == last["value"] and
                      current_input["scanners"] == last["scanners"] and
                      now - last["timestamp"] < 180):
                    remaining = int(180 - (now - last["timestamp"]))
                    st.warning(f"⚠️ A scan with the same input was already triggered. Please wait {remaining} seconds before retrying.")
                else:
                    st.info("⏳ Triggering GitHub Actions workflow...")

                    success, response_text = trigger_workflow(
                        current_input["scan_type"],
                        current_input["value"],
                        enable_syft,
                        enable_grype,
                        enable_scanoss,
                        git_ref_input=current_input["git_ref"]
                    )
                    if success:
                        st.success("✅ Workflow triggered successfully!")

                        # Update last trigger
                        st.session_state.last_trigger = {
                            "scan_type": current_input["scan_type"],
                            "value": current_input["value"],
                            "scanners": current_input["scanners"],
                            "timestamp": now
                        }

                        # Add to history (keep only last 5)
                        st.session_state.scan_history.insert(0, {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "user": user_name.strip(),
                            "scan_type": current_input["scan_type"],
                            "value": current_input["value"],
                            "scanners": ", ".join([
                                s for s, enabled in zip(
                                    ["Syft (SBOM)", "Grype (Vulnerabilities)", "SCANOSS (Licenses)"],
                                    current_input["scanners"]
                                ) if enabled
                            ])
                        })
                        st.session_state.scan_history = st.session_state.scan_history[:5]

                        st.session_state.workflow_url = get_workflow_runs_url()
                    else:
                        st.error(f"❌ Failed to trigger workflow: {response_text}")

        # --- History Panel ---
        if st.session_state.scan_history:
            with st.expander("📜 View Scan History (Last 5)"):
                st.table(st.session_state.scan_history)

# ================= RIGHT: ANI BOT ================= #
with right_col:
    # Scoped CSS for Ani
    st.markdown(
        """
        <style>
        .ani-scope .ani-header {
            display: flex;
            align-items: center;
            font-size: 22px;
            font-weight: bold;
        }
        /* Animated 👩‍💻 icon */
        .ani-scope .ani-icon {
            font-size: 48px;     /* much bigger */
            margin-right: 12px;
            display: inline-block;
            animation: wiggleAni 1.5s infinite ease-in-out;
        }
        @keyframes wiggleAni {
            0%   { transform: rotate(0deg) scale(1); }
            25%  { transform: rotate(-10deg) scale(1.1); }
            50%  { transform: rotate(10deg) scale(1.2); }
            75%  { transform: rotate(-10deg) scale(1.1); }
            100% { transform: rotate(0deg) scale(1); }
        }
        /* Horizontal chip-style question buttons */
        .ani-scope .ani-questions {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        .ani-scope div[data-testid="stButton"] > button {
            background-color: #f8fdf9 !important;
            color: #333 !important;
            border: 1px solid #28a745 !important;
            border-radius: 18px !important;
            padding: 4px 12px !important;
            font-size: 14px !important;
            height: auto !important;
            width: auto !important;
        }
        .ani-scope div[data-testid="stButton"] > button:hover {
            background-color: #e6f8ea !important;
            color: #000 !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="ani-scope">', unsafe_allow_html=True)

    # 👩‍💻 icon instead of 🤖
    st.markdown(
        '<div class="ani-header"><span class="ani-icon">👩‍💻</span> Ani – Help Bot</div>',
        unsafe_allow_html=True
    )

    faq = {
        "How to start scan?": "Enter your name, select scan type (docker/git), provide input, choose scanners, enter password (12345), and click Start Scan.",
        "What is Syft?": "Syft generates a Software Bill of Materials (SBOM).",
        "What is Grype?": "Grype scans for known vulnerabilities (CVEs).",
        "What is SCANOSS?": "SCANOSS identifies open source components and their licenses.",
        "Where are results?": "Click the 🔗 Results button any time to see workflow runs and reports.",
        "Password?": "The default password is 12345 (for demo/testing)."
    }

    if "ani_answer" not in st.session_state:
        st.session_state.ani_answer = None

    if st.session_state.ani_answer is None:
        st.markdown("### I can help with these queries:")
        st.markdown('<div class="ani-questions">', unsafe_allow_html=True)
        for q, a in faq.items():
            if st.button(q, key=f"ani_q_{q}"):
                st.session_state.ani_answer = f"👩‍💻 Ani: {a}"
                st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.success(st.session_state.ani_answer)
        if st.button("🔙 Ask another question", key="ani_back"):
            st.session_state.ani_answer = None
            st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

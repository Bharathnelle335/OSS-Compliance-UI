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

# ---------------- FUNCTIONS ---------------- #
def trigger_workflow(scan_type, value, enable_syft, enable_grype, enable_scanoss):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/workflows/{WORKFLOW_FILE}/dispatches"

    inputs = {
        "scan_type": scan_type,
        "docker_image": value if scan_type == "docker" else "",
        "git_url": value if scan_type == "git" else "",
        "enable_syft": str(enable_syft).lower(),
        "enable_grype": str(enable_grype).lower(),
        "enable_scanoss": str(enable_scanoss).lower()
    }

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
        value = st.text_input("Input Value", placeholder="nginx:latest OR https://github.com/psf/requests")

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
            # Results button ALWAYS active, links to Actions page
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

                        # Store workflow URL immediately (still available if you want)
                        st.session_state.workflow_url = get_workflow_runs_url()
                    else:
                        st.error(f"❌ Failed to trigger workflow: {response_text}")

        # --- History Panel ---
        if st.session_state.scan_history:
            with st.expander("📜 View Scan History (Last 5)"):
                st.table(st.session_state.scan_history)

# ================= RIGHT: ANI BOT ================= #
with right_col:
    # Scope Ani CSS so it doesn't affect Start Scan button
    st.markdown(
        """
        <style>
        .ani-scope .ani-header {
            display: flex;
            align-items: center;
            font-size: 20px;
            font-weight: bold;
        }
        .ani-scope .ani-icon {
            font-size: 28px;
            margin-right: 8px;
            animation: pulseAni 1.5s infinite;
        }
        @keyframes pulseAni {
            0% { transform: scale(1); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }
        .ani-scope .ani-questions {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        /* Only style buttons inside Ani scope */
        .ani-scope div[data-testid="stButton"] > button {
            background-color: #f8fdf9 !important;
            color: #333 !important;
            border: 1px solid #28a745 !important;
            border-radius: 18px !important;
            padding: 4px 10px !important;
            font-size: 13px !important;
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

    st.markdown('<div class="ani-header"><span class="ani-icon">🤖</span> Ani – Help Bot</div>', unsafe_allow_html=True)

    faq = {
        "How to start scan?": "Enter your name, select scan type (docker/git), provide input, choose scanners, enter password (12345), and click Start Scan.",
        "What is Syft?": "Syft generates a Software Bill of Materials (SBOM) listing all dependencies in an image or repo.",
        "What is Grype?": "Grype scans for known vulnerabilities (CVEs) in dependencies and images.",
        "What is SCANOSS?": "SCANOSS identifies open source components and their licenses from source code.",
        "Where are results?": "Click the 🔗 Results button any time to open GitHub Actions → runs & artifacts.",
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

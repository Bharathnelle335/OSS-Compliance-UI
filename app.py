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

st.markdown(
    """
    <style>
    .block-container {padding-top: 0rem;}
    div.stButton > button:first-child {
        background-color: #28a745;
        color: white;
        font-size: 18px;
        font-weight: bold;
        padding: 15px;
        border-radius: 8px;
        width: 100%;
        height: 60px;
    }
    div.stButton > button:first-child:hover {
        background-color:#218838;
        color:white;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------- HEADER ---------------- #
st.markdown(
    """
    <div style="text-align:center; padding-top:60px; padding-bottom:5px;">
        <h2 style="margin-bottom:5px;">OSS Compliance & SBOM Scanner</h2>
        <p style="color:#b30000; font-weight:500; margin-top:0; font-size:14px;">
            For EY Internal Use Only
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# ---------------- MAIN UI ---------------- #
if not TOKEN:
    st.warning("⚠️ No GitHub Token found. Please set `GITHUB_TOKEN` in `.streamlit/secrets.toml`")
else:
    st.subheader("⚙️ Scan Settings")

    # --- Your Name ---
    col1, col2 = st.columns([1,3])
    with col1:
        st.markdown("### Your Name")
    with col2:
        user_name = st.text_input("Your Name", placeholder="Enter your name", label_visibility="collapsed")

    # --- Select Scan Type ---
    col1, col2 = st.columns([1,3])
    with col1:
        st.markdown("### Select Scan Type")
    with col2:
        scan_type = st.selectbox("Scan Type", ["docker", "git"], index=0, label_visibility="collapsed")

    # --- Input Value ---
    col1, col2 = st.columns([1,3])
    with col1:
        st.markdown("### Input Value")
    with col2:
        value = st.text_input("Input Value", placeholder="nginx:latest OR https://github.com/psf/requests", label_visibility="collapsed")

    # --- Select Scanners ---
    col1, col2 = st.columns([1,3])
    with col1:
        st.markdown("### 🛠️ Select Scanners")
    with col2:
        enable_syft = st.checkbox("Syft – Generate SBOM (Software Bill of Materials)", value=True)
        enable_grype = st.checkbox("Grype – Detect vulnerabilities in packages & images", value=True)
        enable_scanoss = st.checkbox("SCANOSS – Identify OSS licenses & components", value=True)

    # --- Password Protection ---
    col1, col2 = st.columns([1,3])
    with col1:
        st.markdown("### Password")
    with col2:
        password = st.text_input("Password", type="password", placeholder="Enter password", label_visibility="collapsed")

    scan_allowed = password == "12345"

    # --- Session state for history/throttling ---
    if "last_trigger" not in st.session_state:
        st.session_state.last_trigger = {"scan_type": None, "value": None, "scanners": None, "timestamp": 0}
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    if "workflow_url" not in st.session_state:
        st.session_state.workflow_url = None

    # --- Start Scan Button ---
    if st.button("🚀 Start Scan", use_container_width=True):
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

                    # Store workflow URL
                    st.session_state.workflow_url = get_workflow_runs_url()
                else:
                    st.error(f"❌ Failed to trigger workflow: {response_text}")

    # --- History Panel ---
    if st.session_state.scan_history:
        with st.expander("📜 View Scan History (Last 5)"):
            st.table(st.session_state.scan_history)

    # --- Persistent Workflow Link ---
    if st.session_state.workflow_url:
        st.markdown(
            f"""
            <div style="margin-top:20px; text-align:center;">
                <a href="{st.session_state.workflow_url}" target="_blank" style="
                    background-color:#28a745;
                    color:white;
                    padding:15px 20px;
                    border-radius:8px;
                    font-weight:bold;
                    text-decoration:none;
                    display:inline-block;
                    width:80%;
                    text-align:center;
                ">
                    🔗 View Workflow Runs & Download Results
                </a>
            </div>
            """,
            unsafe_allow_html=True
        )

# ---------------- HELP BOT (ANI) ---------------- #
st.markdown(
    """
    <style>
    /* Floating chat bubble button */
    .ani-bubble {
        position: fixed;
        top: 20px;
        right: 20px;
        background-color: #28a745;
        border: none;
        border-radius: 50%;
        width: 60px;
        height: 60px;
        font-size: 28px;
        color: white;
        cursor: pointer;
        box-shadow: 0px 4px 12px rgba(0,0,0,0.2);
        animation: pulse 1.8s infinite;
        z-index: 1000;
    }

    /* Pulse animation for highlight */
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(40,167,69, 0.6); }
        70% { box-shadow: 0 0 0 15px rgba(40,167,69, 0); }
        100% { box-shadow: 0 0 0 0 rgba(40,167,69, 0); }
    }

    /* Chatbox styling */
    .ani-chatbox {
        position: fixed;
        top: 80px;
        right: 20px;
        width: 300px;
        background-color: #ffffff;
        border: 2px solid #28a745;
        border-radius: 12px;
        box-shadow: 0px 4px 12px rgba(0,0,0,0.15);
        padding: 10px;
        z-index: 1000;
    }
    .ani-header {
        background-color: #28a745;
        color: white;
        text-align: center;
        padding: 8px;
        border-radius: 10px 10px 0 0;
        font-weight: bold;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .ani-close {
        cursor: pointer;
        font-size: 16px;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Session toggle for Ani visibility
if "ani_open" not in st.session_state:
    st.session_state.ani_open = False

# Floating chat bubble
bubble_html = """
    <form action="#" method="get">
        <button class="ani-bubble" name="ani_click">💬</button>
    </form>
"""
st.markdown(bubble_html, unsafe_allow_html=True)

# Check query param hack for toggle
params = st.experimental_get_query_params()
if "ani_click" in params:
    st.session_state.ani_open = not st.session_state.ani_open
    st.experimental_set_query_params()  # reset URL

# Ani chatbox content
if st.session_state.ani_open:
    with st.container():
        st.markdown('<div class="ani-chatbox">', unsafe_allow_html=True)
        st.markdown(
            '<div class="ani-header">👩‍💻 Ani – Help Bot <span class="ani-close">❌</span></div>',
            unsafe_allow_html=True
        )

        faq = {
            "How to start scan?": "Enter your name, select scan type (docker/git), provide input, choose scanners, enter password (12345), and click Start Scan.",
            "What is Syft?": "Syft generates a Software Bill of Materials (SBOM) listing all dependencies in an image or repo.",
            "What is Grype?": "Grype scans for known vulnerabilities (CVEs) in dependencies and images.",
            "What is SCANOSS?": "SCANOSS identifies open source components and their licenses from source code.",
            "Where are results?": "Once scan is triggered, you can find reports in GitHub Actions → Artifacts. The UI also provides a direct link.",
            "Password?": "The default password is 12345 (for demo/testing)."
        }

        question = st.selectbox("💬 Ask Ani", [""] + list(faq.keys()), key="ani_selectbox")

        if question:
            st.success(f"👩‍💻 Ani: {faq[question]}")

        st.markdown("</div>", unsafe_allow_html=True)

        # ❌ Close button JS (simulate click)
        st.markdown(
            """
            <script>
            const closeBtn = window.parent.document.querySelector('.ani-close');
            if (closeBtn) {
                closeBtn.onclick = function() {
                    window.parent.location.href = window.parent.location.pathname;
                }
            }
            </script>
            """,
            unsafe_allow_html=True
        )


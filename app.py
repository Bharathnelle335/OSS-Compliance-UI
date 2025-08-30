import streamlit as st
import requests
import time
from datetime import datetime

# ---------------- CONFIG ---------------- #
OWNER = "Bharathnelle335"
REPO = "Universal-OSS-Compliance"
WORKFLOW_FILE = "oss-compliance.yml"   # Must match workflow filename in backend repo
BRANCH = "main"

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

# ---------------- MAIN LAYOUT ---------------- #
left_col, right_col = st.columns([7, 3])

# ================= LEFT: SCAN SETTINGS ================= #
with left_col:
    if not TOKEN:
        st.warning("⚠️ No GitHub Token found. Please set `GITHUB_TOKEN` in `.streamlit/secrets.toml`")
    else:
        st.subheader("⚙️ Scan Settings")

        # --- Inputs ---
        user_name = st.text_input("Your Name", placeholder="Enter your name")
        scan_type = st.selectbox("Select Scan Type", ["docker", "git"], index=0)
        value = st.text_input("Input Value", placeholder="nginx:latest OR https://github.com/psf/requests")

        st.markdown("### 🛠️ Select Scanners")
        enable_syft = st.checkbox("Syft – Generate SBOM (Software Bill of Materials)", value=True)
        enable_grype = st.checkbox("Grype – Detect vulnerabilities in packages & images", value=True)
        enable_scanoss = st.checkbox("SCANOSS – Identify OSS licenses & components", value=True)

        # --- Password + Start Scan + Results in same row ---
        col1, col2, col3 = st.columns([2,1,1])
        with col1:
            password = st.text_input("Password", type="password", placeholder="Enter password")

        with col2:
            # hidden button for backend logic
            trigger_scan = st.button("hidden_scan_trigger", key="scan_trigger", help="hidden", label_visibility="collapsed")
            st.markdown(
                """
                <button onclick="window.parent.postMessage({type: 'scan'}, '*')" style="
                    background-color:#28a745;
                    color:white;
                    padding:10px 12px;
                    border-radius:6px;
                    font-weight:bold;
                    border:none;
                    cursor:pointer;
                    display:inline-block;
                    width:100%;
                    height:45px;
                    text-align:center;
                    line-height:25px;
                ">
                    🚀 Start Scan
                </button>
                """,
                unsafe_allow_html=True
            )

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

        # --- Session state ---
        if "scan_history" not in st.session_state:
            st.session_state.scan_history = []

        # --- Scan Logic ---
        if trigger_scan:
            if not scan_allowed:
                st.error("❌ Invalid password. Access denied.")
            elif value.strip() == "":
                st.error("⚠️ Please provide an input value before starting the scan.")
            elif user_name.strip() == "":
                st.error("⚠️ Please enter your name before triggering the scan.")
            else:
                st.info("⏳ Triggering GitHub Actions workflow...")
                success, response_text = trigger_workflow(
                    scan_type, value.strip(),
                    enable_syft, enable_grype, enable_scanoss
                )
                if success:
                    st.success("✅ Workflow triggered successfully!")

                    st.session_state.scan_history.insert(0, {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "user": user_name.strip(),
                        "scan_type": scan_type,
                        "value": value.strip(),
                        "scanners": ", ".join([
                            s for s, enabled in zip(
                                ["Syft (SBOM)", "Grype (Vulnerabilities)", "SCANOSS (Licenses)"],
                                (enable_syft, enable_grype, enable_scanoss)
                            ) if enabled
                        ])
                    })
                    st.session_state.scan_history = st.session_state.scan_history[:5]
                else:
                    st.error(f"❌ Failed to trigger workflow: {response_text}")

        # --- History Panel ---
        if st.session_state.scan_history:
            with st.expander("📜 View Scan History (Last 5)"):
                st.table(st.session_state.scan_history)

# ================= RIGHT: ANI BOT ================= #
with right_col:
    st.markdown(
        """
        <style>
        .ani-header {
            display: flex;
            align-items: center;
            font-size: 20px;
            font-weight: bold;
        }
        .ani-icon {
            font-size: 28px;
            margin-right: 8px;
            animation: pulseAni 1.5s infinite;
        }
        @keyframes pulseAni {
            0% { transform: scale(1); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }
        .ani-questions {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        div[data-testid="stButton"] > button {
            background-color: #f8fdf9 !important;
            color: #333 !important;
            border: 1px solid #28a745 !important;
            border-radius: 18px !important;
            padding: 4px 10px !important;
            font-size: 13px !important;
            height: auto !important;
            width: auto !important;
        }
        div[data-testid="stButton"] > button:hover {
            background-color: #e6f8ea !important;
            color: #000 !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="ani-header"><span class="ani-icon">🤖</span> Ani – Help Bot</div>', unsafe_allow_html=True)

    faq = {
        "How to start scan?": "Enter your name, select scan type (docker/git), provide input, choose scanners, enter password (12345), and click Start Scan.",
        "What is Syft?": "Syft generates a Software Bill of Materials (SBOM).",
        "What is Grype?": "Grype scans for known vulnerabilities (CVEs).",
        "What is SCANOSS?": "SCANOSS identifies open source components and licenses.",
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

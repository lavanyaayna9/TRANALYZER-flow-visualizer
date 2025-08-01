import streamlit as st
import os
import subprocess
from db_utils import save_flows_to_sqlite
import pandas as pd

st.set_page_config(
    page_title="Tranalyzer Flow Visualizer",
    layout="centered",
    initial_sidebar_state="expanded"
)

# --- Custom CSS Styling ---
st.markdown("""
<style>
/* General Layout */
html, body, .stApp {
    background: linear-gradient(90deg, #331C33 0%, #2D1A70 50%, #2D1C33 100%);
    color: white;
    font-family: 'Poppins', 'Segoe UI', sans-serif;
    transition: background-color 0.5s ease;
}

/* Title */
.main-title {
    font-size: 3.6rem;
    font-weight: 800;
    text-align: center;
    margin-top: 4rem;
    color: white;
    text-shadow: 0 4px 16px rgba(0, 0, 0, 0.6);
    animation: fadeInSlide 1s ease-out;
}

/* File uploader */
.stFileUploader > div > div {
    background-color: #2c3e50;
    border: 3px dashed #64b5f6;
    border-radius: 15px;
    padding: 3rem;
    transition: all 0.3s ease-in-out;
    cursor: pointer;
}
.stFileUploader > div > div:hover {
    border-color: #90caf9;
    background-color: #3d5168;
    transform: scale(1.03);
}
.stFileUploader span {
    color: black !important;
    font-weight: bold;
}

/* Unified message box (upload + complete + BRIEF SUMMARY label) */
.stSuccess, .stInfo {
    background-color: #1e1e1e !important;
    color: white !important;
    border-radius: 12px;
    padding: 1.4rem 2rem;
    margin-top: 2rem;
    font-size: 1.15rem;
    font-weight: 600;
    text-align: center;
    width: fit-content;
    margin-left: auto;
    margin-right: auto;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    animation: slideIn 0.5s ease-out;
}
.stError {
    background-color: #d32f2f !important;
    color: white !important;
    border-radius: 12px;
    padding: 1.4rem 2rem;
    margin-top: 2rem;
    font-size: 1.15rem;
    font-weight: 600;
    text-align: center;
    width: fit-content;
    margin-left: auto;
    margin-right: auto;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}
@keyframes slideIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Spinner */
.stSpinner > div {
    color: #64b5f6 !important;
    font-size: 1.3rem;
}

/* Debug summary box */
.debug-box {
    background-color: #1e1e1e !important;
    padding: 1.8rem;
    border-radius: 15px;
    color: #a7d9b9 !important;
    font-family: 'Fira Code', 'Consolas', monospace;
    font-size: 0.97rem;
    margin-top: 1rem;
    width: 95%;
    max-width: 800px;
    text-align: left;
    border: 1px solid rgba(255, 255, 255, 0.1);
    overflow-x: auto;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-word;
    margin-left: auto;
    margin-right: auto;
    box-shadow: inset 0 0 8px rgba(0, 0, 0, 0.2);
    max-height: 340px;
}

/* Button styling */
div.stButton > button {
    background-color: #4CAF50;
    color: white;
    padding: 1rem 2rem;
    border-radius: 10px;
    border: none;
    font-size: 1.18rem;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.2s;
}
div.stButton > button:hover {
    background-color: #45a049;
    transform: translateY(-2px);
}
</style>
""", unsafe_allow_html=True)

# Main Container
st.markdown('<div class="main-title">TRANALYZER FLOW VISUALIZER</div>', unsafe_allow_html=True)

# File Uploader Section
st.markdown(
    "<h4 style='text-align:center;margin-bottom:1.7rem;'>Drop your <b>.pcap</b> file to analyze (max 500MB):</h4>",
    unsafe_allow_html=True
)
uploaded_file = st.file_uploader("Upload a pcap file", type=["pcap"], label_visibility="collapsed")
st.markdown("</div>", unsafe_allow_html=True)

# --- File Upload Logic ---
if uploaded_file:
    if uploaded_file.size > 500 * 1024 * 1024:
        st.error("File size exceeds 500 MB. Please upload a smaller pcap file.")
        st.stop()
    output_base_dir = "./sf_Wireshark-1"
    os.makedirs(output_base_dir, exist_ok=True)
    save_path = os.path.join(output_base_dir, "uploaded_file.pcap")
    with open(save_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(" File uploaded successfully! Preparing for analysis...")

    with st.spinner("Analyzing the file using Tranalyzer2. This might take a moment..."):
        t2_path = "/home/lavanya/tranalyzer2-0.9.3/tranalyzer2/build/tranalyzer"
        t2_command = [t2_path, "-r", save_path, "-w", output_base_dir]
        try:
            process = subprocess.run(t2_command, capture_output=True, text=True)
            st.success(" Analysis complete! You can now view the Dashboard.")

            if process.stdout:
                st.info("BRIEF SUMMARY:")
                st.markdown(f"<div class='debug-box' style='color: #a7d9b9;'>{process.stdout[-2000:]}</div>", unsafe_allow_html=True)

            # --- NEW: Save flows to DB ---
            output_txt = os.path.join(output_base_dir, "uploaded_file_flows.txt")
            if os.path.exists(output_txt):
                try:
                    df = pd.read_csv(output_txt, sep="\t", low_memory=False)
                    session_id = save_flows_to_sqlite(df)  # <- DB integration
                    st.success(f"Results saved! Session ID: {session_id[:8]}")
                except Exception as e:
                    st.error(f"Could not save flows to database: {e}")
            else:
                st.warning("Tranalyzer did not produce an output file. No results to save.")

        except subprocess.CalledProcessError as e:
            st.error("❌ Analysis failed. Please check the file and Tranalyzer2 setup.")
            st.markdown(f"<div class='debug-box'>Error Code: {e.returncode}<br>STDOUT: {e.stdout}<br>STDERR: {e.stderr}</div>", unsafe_allow_html=True)
        except FileNotFoundError:
            st.error(f"❌ Tranalyzer2 executable not found at: `{t2_path}`. Please verify the path.")
        except Exception as e:
            st.error(f"❌ An unexpected error occurred during analysis: {e}")
            st.markdown(f"<div class='debug-box'>Error Details: {e}</div>", unsafe_allow_html=True)


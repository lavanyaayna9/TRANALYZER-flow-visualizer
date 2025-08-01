import streamlit as st

st.set_page_config(
    page_title="Welcome - Tranalyzer Flow Visualizer",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;800&family=Fira+Sans:ital,wght@0,400;0,700;1,400&display=swap');

html, body, .stApp {
    background: linear-gradient(90deg, #2D1C33 0%, #2D1A70 50%, #2D1C33 100%);
    color: #ffffff;
    font-family: 'Poppins', sans-serif;
}

/* Center all Streamlit buttons on the page */
div.stButton {
    display: flex;
    justify-content: center;
    align-items: center;
}

/* Button style */
div.stButton > button {
    background-color: #F5F5F5;
    color: black;
    font-size: 1.25rem;
    padding: 0.9rem 2.4rem;
    border: none;
    border-radius: 12px;
    cursor: pointer;
    animation: pulseGlow 2.4s infinite;
    transition: transform 0.3s ease;
    margin: 0.5rem 0 0.5rem 0;
    box-shadow: 0 0 0px rgba(72,239,120,0.6);
}
div.stButton > button:hover {
    transform: scale(1.05);
}
div.stButton > button:focus {
    outline: none;
    box-shadow: 0 0 10px #4CAF50;
}

.main-title {
    font-size: 3.6rem;
    font-weight: 800;
    text-align: center;
    margin-top: 4rem;
    color: white;
    text-shadow: 0 4px 16px rgba(0, 0, 0, 0.6);
    animation: fadeInSlide 1s ease-out;
}

.description {
    font-family: 'Fira Sans', sans-serif;
    font-style: italic;
    font-weight: 400;
    font-size: 1.35rem;
    text-align: center;
    margin: 2rem auto 2.6rem auto;
    max-width: 800px;
    color: #f0f0f0;
    line-height: 1.7;
    animation: fadeInSlide 1.4s ease-out;
}

@keyframes fadeInSlide {
    0%   { opacity: 0; transform: translateY(30px); }
    100% { opacity: 1; transform: translateY(0); }
}
@keyframes pulseGlow {
    0%   { box-shadow: 0 0 0px rgba(72,239,120,0.6); }
    50%  { box-shadow: 0 0 20px rgba(72,239,120,0.9); }
    100% { box-shadow: 0 0 0px rgba(72,239,120,0.6); }
}
</style>
""", unsafe_allow_html=True)

# ---------- CONTENT ----------
st.markdown('<div class="main-title">TRANALYZER FLOW VISUALIZER</div>', unsafe_allow_html=True)

st.markdown('<div class="description">Visualize and explore your network traffic with ease. Tranalyzer Flow Visualizer turns complex PCAP files into interactive dashboards, helping you understand IP activity, protocol usage, and communication patterns—making network analysis simple and insightful.</div>', unsafe_allow_html=True)
if st.button("Start Analyzer"):
    st.switch_page("pages/1_Upload_pcap.py")

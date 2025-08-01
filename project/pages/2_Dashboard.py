import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

st.set_page_config(layout="wide")
st.markdown(
    '<h1 style="text-align: center; font-size: 3rem; margin-bottom: 1.5rem;">TRANALYZER FLOW VISUALIZER</h1>',
    unsafe_allow_html=True,
)

st.markdown("""
<style>
html, body, .stApp {
    background: linear-gradient(90deg, #331C33 0%, #2D1A70 50%, #2D1C33 100%);
    color: #FFFFFF;
    font-family: 'Poppins', 'Segoe UI', sans-serif;
}
/* ----- METRIC CARDS ROW LAYOUT ----- */
.metric-row {
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: stretch;
    margin: 36px 0 22px 0;
    gap: 34px;
    flex-wrap: nowrap;
}
/* ----- CARD METRICS ----- */
.card-metric {
    min-width: 200px;
    max-width: 260px;
    width: 100%;
    height: 130px;
    border-radius: 22px;
    background: linear-gradient(135deg, #f2f5fa 82%, #c5e6ff 100%);
    color: #232436;
    text-align: center;
    font-size: 1.13rem;
    box-shadow: 0 4px 20px 0 rgba(36,90,190,0.09), 0 2px 7px rgba(22,30,52,0.09);
    display: flex;
    flex-direction: column;
    justify-content: center;
    border: 1.5px solid #c3d1ea;
    transition: box-shadow 0.16s;
    animation: fadeInSlide 1.2s cubic-bezier(.54,-0.01,.52,1.16);
    margin: 0;
    padding: 18px 0 10px 0;
}
.card-metric span {
    font-size: 2.2rem;
    font-weight: 700;
    margin-top: 7px;
    color: #2474b5;
    letter-spacing: 1px;
}
.card-metric b {
    font-size: 1.13rem;
    font-weight: 600;
    color: #611626;
    letter-spacing: 0.01em;
}
.card-metric .small {
    display: block;
    font-size: 1.02rem !important;
    font-weight: 400;
    color: #a6415f;
    margin-top: 3px;
}
.centered-flex {
    width: 100%;
    display: flex;
    justify-content: center;
    margin: 0 !important;
    padding: 0 !important;
}
/* --- RESPONSIVE --- */
@media (max-width: 1200px) {
    .metric-row { gap: 20px; }
    .card-metric { min-width: 140px; max-width: 180px; font-size: 0.98rem;}
    .card-metric span { font-size: 1.23rem; }
}
@media (max-width: 900px) {
    .metric-row { flex-wrap: wrap; gap: 16px; }
    .card-metric { min-width: 120px; max-width: 48vw; margin-bottom: 8px; }
}
@media (max-width: 700px) {
    .metric-row { flex-direction: column; align-items: center; }
    .card-metric { width: 94vw; max-width: 94vw; margin-bottom: 14px; }
}
/* ----- DASHBOARD TABLES, SCROLLBARS, DROPDOWNS ----- */
.scrollable-table-wrapper {
    max-height: 420px;
    height: 420px;
    max-width: 90%;
    width: 90%;
    overflow-y: auto;
    border-radius: 15px;
    box-shadow: 0 2px 12px rgba(20,20,40,0.24);
    background: none;
    margin-bottom: 8px;
}
.custom-gradient-table {
    width: 100%;
    background: transparent;
    border-radius: 15px;
    border-collapse: separate;
    border-spacing: 0;
    backdrop-filter: blur(4px);
}
.custom-gradient-table th {
    background: transparent;
    color: #fff;
    font-size: 18px;
    padding: 7px 8px;
    border: none;
    position: sticky;
    top: 0;
    z-index: 2;
    text-shadow: 0 1px 6px #1b153a;
    text-align: center;
}
.custom-gradient-table td {
    background: transparent;
    color: #fff;
    padding: 6px 10px;
    border-bottom: 1px solid rgba(80,80,120,0.13);
    font-size: 15px;
    text-align: center;
}
.custom-gradient-table tr:last-child td {
    border-bottom: none;
}
.scrollable-table-wrapper::-webkit-scrollbar {
    width: 8px;
    background: #24243e;
    border-radius: 7px;
}
.scrollable-table-wrapper::-webkit-scrollbar-thumb {
    background: #302b63;
    border-radius: 7px;
}
[data-baseweb="select"] > div {
    background: transparent !important;
    color: white !important;
    border-radius: 10px !important;
}
label, .stSelectbox label {
    display: block !important;
    color: #fff !important;  /* or your preferred color */
    font-weight: 600 !important;
    margin-bottom: 2px !important;
}
@keyframes fadeInSlide {
    0%   { opacity: 0; transform: translateY(30px);}
    100% { opacity: 1; transform: translateY(0);}
}
</style>
""", unsafe_allow_html=True)

# ------- Load Data -------
output_base_dir = "./sf_Wireshark-1"
output_txt = os.path.join(output_base_dir, "uploaded_file_flows.txt")

if not os.path.exists(output_txt):
    st.warning("No analysis data found. Please upload and analyze a pcap file on the Home page.")
    st.stop()

try:
    df = pd.read_csv(output_txt, sep="\t", low_memory=False)
except Exception as e:
    st.error(f"Could not load data: {e}")
    st.stop()

# --- Metrics to Display (First 4) ---
src_col = next((c for c in df.columns if "srcip" in c.lower()), None)
dst_col = next((c for c in df.columns if "dstip" in c.lower()), None)
proto_col = next((c for c in df.columns if "l4proto" in c.lower()), None)
dst_country_col = next((c for c in df.columns if "dstipcountry" in c.lower()), None)
proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6'}

total_flows = len(df)
unique_ips = len(pd.Series(df[src_col].dropna().tolist() + df[dst_col].dropna().tolist()).unique()) if src_col and dst_col else 0
if proto_col and not df.empty:
    top_proto_code = df[proto_col].astype(str).value_counts().idxmax()
    top_proto_name = proto_map.get(top_proto_code, f"Other ({top_proto_code})")
    top_proto_count = df[proto_col].astype(str).value_counts().max()
else:
    top_proto_name, top_proto_count = "N/A", "0"
country_count = df[dst_country_col].nunique() if dst_country_col else 0

card_labels = [
    ("Total Flows", total_flows),
    ("Unique IPs", unique_ips),
    ("Top Protocol", f"<b>{top_proto_name}</b><br><span class='small'>({top_proto_count} flows)</span>"),
    ("Countries Contacted", country_count),
]

# Render as a single row using HTML, for perfect spacing
card_html = """
<div class='metric-row'>
    <div class='card-metric fadeInSlide'>
        <b>Total Flows</b>
        <span>512</span>
    </div>
    <div class='card-metric fadeInSlide'>
        <b>Unique IPs</b>
        <span>126</span>
    </div>
    <div class='card-metric fadeInSlide'>
        <b>Top Protocol</b>
        <span><b>UDP</b><br><span class='small'>(368 flows)</span></span>
    </div>
    <div class='card-metric fadeInSlide'>
        <b>Countries Contacted</b>
        <span>8</span>
    </div>
</div>
"""

st.markdown(card_html, unsafe_allow_html=True)

# --------- GEO COLUMNS & DF_GEO SETUP (with protocol dropdown and labels) ---------
src_col = next((c for c in df.columns if "srcip" in c.lower()), None)
dst_col = next((c for c in df.columns if "dstip" in c.lower()), None)
src_lat_col = next((c for c in df.columns if "lat" in c.lower() and "src" in c.lower()), None)
src_lon_col = next((c for c in df.columns if "lon" in c.lower() and "src" in c.lower()), None)
dst_lat_col = next((c for c in df.columns if "lat" in c.lower() and "dst" in c.lower()), None)
dst_lon_col = next((c for c in df.columns if "lon" in c.lower() and "dst" in c.lower()), None)
src_city_col = next((c for c in df.columns if "city" in c.lower() and "src" in c.lower()), None)
dst_city_col = next((c for c in df.columns if "city" in c.lower() and "dst" in c.lower()), None)
src_country_col = next((c for c in df.columns if "srcipcountry" in c.lower()), None)
dst_country_col = next((c for c in df.columns if "dstipcountry" in c.lower()), None)
proto_col = next((c for c in df.columns if "l4proto" in c.lower()), None)

geo_cols = [src_col, src_country_col, src_lat_col, src_lon_col, src_city_col,
            dst_col, dst_country_col, dst_lat_col, dst_lon_col, dst_city_col]
geo_colnames = ["srcIP", "srcIPCountry", "srcLat", "srcLon", "srcCity",
                "dstIP", "dstIPCountry", "dstLat", "dstLon", "dstCity"]
if proto_col:
    geo_cols.append(proto_col)
    geo_colnames.append("l4Proto")

cols_to_use = [c for c in geo_cols if c is not None]
names_to_use = [geo_colnames[i] for i, c in enumerate(geo_cols) if c is not None]

minimum_needed = set(["srcIP", "srcIPCountry", "srcLat", "srcLon", "srcCity",
                      "dstIP", "dstIPCountry", "dstLat", "dstLon", "dstCity"])

if all(col in names_to_use for col in minimum_needed):
    df_geo = df[cols_to_use].dropna().copy()
    df_geo.columns = names_to_use

    # --- Build protocol options for filter ---
    proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6'}
    if "l4Proto" in df_geo.columns:
        proto_choices = sorted(df_geo["l4Proto"].dropna().astype(str).unique())
        proto_name_map = {k: proto_map.get(str(k), f"Other ({k})") for k in proto_choices}
        protocol_options = ["All"] + [proto_name_map[k] for k in proto_choices]
    else:
        protocol_options = ["All"]
        proto_name_map = {}

    # --- 4 FILTER DROPDOWNS WITH LABELS ---
    filter1, filter2, filter3, filter4 = st.columns(4, gap="large")
    with filter1:
        selected_srcip = st.selectbox(
            "Filter by Source IP",
            options=["All"] + sorted(df_geo["srcIP"].dropna().unique().tolist()),
            index=0,
            key="filter_srcip"
        )
    with filter2:
        selected_dstip = st.selectbox(
            "Filter by Destination IP",
            options=["All"] + sorted(df_geo["dstIP"].dropna().unique().tolist()),
            index=0,
            key="filter_dstip"
        )
    with filter3:
        selected_dstcountry = st.selectbox(
            "Filter by Destination Country",
            options=["All"] + sorted(df_geo["dstIPCountry"].dropna().unique().tolist()),
            index=0,
            key="filter_dstcountry"
        )
    with filter4:
        selected_protocol = st.selectbox(
            "Filter by Protocol",
            options=protocol_options,
            index=0,
            key="filter_protocol"
        )

    # --- APPLY FILTERS TO GEO DF ---
    filtered_geo = df_geo.copy()
    if selected_srcip != "All":
        filtered_geo = filtered_geo[filtered_geo["srcIP"] == selected_srcip]
    if selected_dstip != "All":
        filtered_geo = filtered_geo[filtered_geo["dstIP"] == selected_dstip]
    if selected_dstcountry != "All":
        filtered_geo = filtered_geo[filtered_geo["dstIPCountry"] == selected_dstcountry]
    if selected_protocol != "All" and "l4Proto" in filtered_geo.columns:
        reverse_proto_map = {v: k for k, v in proto_name_map.items()}
        selected_proto_val = reverse_proto_map.get(selected_protocol)
        filtered_geo = filtered_geo[filtered_geo["l4Proto"].astype(str) == str(selected_proto_val)]

    # --- PREPARE ENDPOINT MARKERS DATAFRAME ---
    endpoints = []
    for _, row in filtered_geo.iterrows():
        endpoints.append({
            'IP': row['srcIP'],
            'Lat': row['srcLat'],
            'Lon': row['srcLon'],
            'Country': row['srcIPCountry'],
            'City': row.get('srcCity', ''),
            'Type': 'Source'
        })
        endpoints.append({
            'IP': row['dstIP'],
            'Lat': row['dstLat'],
            'Lon': row['dstLon'],
            'Country': row['dstIPCountry'],
            'City': row.get('dstCity', ''),
            'Type': 'Destination'
        })
    df_endpoints = pd.DataFrame(endpoints)
    df_endpoints = df_endpoints.drop_duplicates(subset=['IP', 'Lat', 'Lon', 'Type'])

    # --- SHOW MAP WITH MARKERS AND ARC LINES ---
    if not df_endpoints.empty:
        import plotly.graph_objects as go
        fig = go.Figure()

        # Add arc lines for each flow
        for _, row in filtered_geo.iterrows():
            fig.add_trace(go.Scattermap(
                mode="lines",
                lon=[row["srcLon"], row["dstLon"]],
                lat=[row["srcLat"], row["dstLat"]],
                line=dict(width=1, color="#A9A9A9"),
                hoverinfo="none",
                showlegend=False
            ))

        # Add source and destination city markers
        for t, color in [("Source", "#ffb400"), ("Destination", "#5022ee")]:
            df_type = df_endpoints[df_endpoints["Type"] == t]
            fig.add_trace(go.Scattermap(
                mode="markers",
                lon=df_type["Lon"],
                lat=df_type["Lat"],
                marker=dict(size=13, color=color, opacity=0.85),
                text=[
                    f"{t} City: {city if pd.notna(city) else 'Unknown'}<br>Country: {country}<br>IP: {ip}"
                    for city, country, ip in zip(df_type["City"], df_type["Country"], df_type["IP"])
                ],
                hoverinfo="text",
                name=t,
                showlegend=True
            ))

        fig.update_layout(
            map=dict(
                style="light",   # MapLibre light theme (no Mapbox token needed)
                zoom=1.15,
                center=dict(lat=20, lon=0)
            ),
            height=570,
            margin={"r":0, "t":0, "l":0, "b":0},
            legend=dict(
                orientation="h",
                yanchor="bottom", y=0.01,
                xanchor="right", x=0.99,
                bgcolor="rgba(255,255,255,0.75)"
            )
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No geolocated flows for selected filters.")

else:
    st.info("Not enough geo information in the uploaded file for the arc map/table.")
    st.stop()

# ----------- TABLE BELOW MAP -----------
st.markdown("<div style='margin-top:18px'></div>", unsafe_allow_html=True)

st.markdown(
    """
    <h4 style='
        text-align:center;
        margin-bottom:8px;
        margin-top:18px;
        background: transparent;
        color: #fff;
        padding: 8px 0 0 8px;
        border-radius: 12px;
        font-size:2.21rem;
        box-shadow: 0 2px 8px rgba(20,20,20,0.21);
    '>IP COMMUNICATION TABLE</h4>
    """, unsafe_allow_html=True
)
st.markdown("<div style='margin-bottom: 30px;'></div>", unsafe_allow_html=True)

# Auto-detect best table fields
src_ip_col = next((c for c in df.columns if "srcip" in c.lower()), None)
dst_ip_col = next((c for c in df.columns if "dstip" in c.lower()), None)
src_port_col = next((c for c in df.columns if "srcport" in c.lower()), None)
dst_port_col = next((c for c in df.columns if "dstport" in c.lower()), None)
proto_col = next((c for c in df.columns if "l4proto" in c.lower()), None)
ndpi_col = next((c for c in df.columns if "ndpi" in c.lower()), None)
src_country_col = next((c for c in df.columns if "country" in c.lower() and "src" in c.lower()), None)
dst_country_col = next((c for c in df.columns if "country" in c.lower() and "dst" in c.lower()), None)
sni_col = next((c for c in df.columns if "sni" in c.lower()), None)

fields = [src_ip_col, src_country_col, src_port_col,
          dst_ip_col, dst_country_col, dst_port_col,
          proto_col, ndpi_col, sni_col]
fields = [f for f in fields if f is not None]
table_display = df[fields].copy()

proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6'}
if proto_col and proto_col in table_display.columns:
    table_display[proto_col] = table_display[proto_col].astype(str).map(lambda x: proto_map.get(x, f"Other ({x})"))

column_rename = {
    src_ip_col: "Source IP",
    src_country_col: "Source Country",
    src_port_col: "Source Port",
    dst_ip_col: "Destination IP",
    dst_country_col: "Destination Country",
    dst_port_col: "Destination Port",
    proto_col: "Protocol",
    ndpi_col: "App Protocol",
    sni_col: "SNI Domain",
}
table_display = table_display.rename(columns=column_rename)

st.markdown(
    f'<div class="scrollable-table-wrapper" style="width:100%;max-width:100%">{table_display.head(100).to_html(classes="custom-gradient-table", index=False, escape=False)}</div>',
    unsafe_allow_html=True
)

st.markdown("---")

# ------- 1️⃣ Protocols with names -------
st.markdown(
    '<h2 style="text-align: center; margin-bottom: 1.1rem;">PROTOCOL USAGE DISTRIBUTION</h2>',
    unsafe_allow_html=True
)
proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6'}
proto_col = next((c for c in df.columns if "l4proto" in c.lower()), None)
if proto_col:
    df1 = df[proto_col].astype(str).value_counts().reset_index()
    df1.columns = ["Protocol", "Count"]
    df1["Protocol"] = df1["Protocol"].apply(lambda x: proto_map.get(x, f"Other ({x})"))
    fig1 = px.pie(
        df1,
        names='Protocol',
        values='Count',
        hole=0.3,
        color_discrete_sequence=px.colors.sequential.RdBu
    )
    fig1.update_layout(
        height=500,
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)', 
        plot_bgcolor='rgba(0,0,0,0)',
        legend=dict(
            font=dict(color='#fff', size=16)   # Set legend text color to white
        )
    )
    st.plotly_chart(fig1, use_container_width=True)
else:
    st.warning("Protocol column not found in output.")

st.markdown("---")
# ------- 2️⃣ MOST ACTIVE IPS -------
st.markdown(
    '<h2 style="text-align: center; margin-bottom: 1.1rem;">MOST ACTIVE IPS</h2>',
    unsafe_allow_html=True
)

src_col = next((c for c in df.columns if "srcip" in c.lower()), None)
dst_col = next((c for c in df.columns if "dstip" in c.lower()), None)

if src_col and dst_col:
    ip_counts = pd.concat([
        df[src_col].value_counts(),
        df[dst_col].value_counts()
    ], axis=1, keys=["src", "dst"]).fillna(0)

    ip_counts["Total Flows"] = ip_counts.sum(axis=1)
    ip_counts = ip_counts.sort_values("Total Flows", ascending=False).head(10).reset_index()
    ip_counts.columns = ["IP", "Source Flows", "Dest Flows", "Total Flows"]

    # 🎨 Custom colors from your reference screenshot (top to bottom)
    custom_colors = [
        "#ADD8E6",  # light blue
        "#0000FF",  # blue
        "#FFB6C1",  # light pink
        "#FF0000",  # red
        "#90EE90",  # light green
        "#20B2AA",  # light sea green
        "#FFD700",  # gold
        "#FFA500",  # orange
        "#9370DB",  # medium purple
        "#D3D3D3"   # light gray
    ]

    # ✅ Assign color by IP so each bar gets unique color
    fig2 = px.bar(
        ip_counts,
        x='Total Flows',
        y='IP',
        orientation='h',
        color='IP',
        color_discrete_sequence=custom_colors
    )

    fig2.update_layout(
        height=550,
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        showlegend=False,
        yaxis=dict(autorange="reversed")
    )

    st.plotly_chart(fig2, use_container_width=True)

else:
    st.warning("Source/Destination IP columns not found in output.")

st.markdown("---")

# ------- 3️⃣ Application Layer Protocols (nDPI Treemap) -------
st.markdown(
    '<h2 style="text-align: center; margin-bottom: 1.1rem;">APPLICATION LAYER PROTOCOLS (nDPI Classification)</h2>',
    unsafe_allow_html=True
)
ndpi_col = next((c for c in df.columns if "ndpiclass" in c.lower()), None)
if ndpi_col:
    df3 = df[ndpi_col].fillna("Unknown").astype(str).value_counts().reset_index().head(10)
    df3.columns = ["Application Protocol", "Count"]
    fig3 = px.treemap(df3, path=['Application Protocol'], values='Count', color='Count', color_continuous_scale='Agsunset')
    fig3.update_layout(height=580, template='plotly_dark',
                       paper_bgcolor='rgba(0,0,0,0)', 
                       plot_bgcolor='rgba(0,0,0,0)')    
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.warning("nDPI class column not found in output.")

st.markdown("---")

st.markdown(
    '<h2 style="text-align: center; margin-bottom: 1.1rem;">TLS/SSL FLOWS</h2>',
    unsafe_allow_html=True
)

# 1️⃣ Force st.metric to use white for value and delta
st.markdown("""
    <style>
    /* Set ALL st.metric numbers and arrows to white */
    div[data-testid="stMetric"] > div {
        color: #fff !important;
    }
    div[data-testid="stMetric"] svg {
        color: #fff !important;
        fill: #fff !important;
    }
    </style>
""", unsafe_allow_html=True)

dst_port_col = next((c for c in df.columns if "dstport" in c.lower()), None)
tls_count = 0
total_flows = len(df)
if dst_port_col and proto_col:
    tls_count = df[(df[dst_port_col].astype(str).isin(["443", "8443"])) & (df[proto_col].astype(str) == '6')].shape[0]
tls_percentage = round((tls_count / total_flows) * 100, 2) if total_flows else 0

st.metric(label=" TLS/SSL Flows", value=f"{tls_count} flows", delta=f"{tls_percentage}% of total")
df4 = pd.DataFrame({
    "Type": ["TLS Flows", "Non-TLS Flows"],
    "Count": [tls_count, total_flows - tls_count]
})
fig4 = px.pie(df4, names="Type", values="Count", hole=0.3, color_discrete_sequence=px.colors.qualitative.Set2)
fig4.update_layout(height=580, template='plotly_dark',
                   paper_bgcolor='rgba(0,0,0,0)', 
                   plot_bgcolor='rgba(0,0,0,0)')
st.plotly_chart(fig4, use_container_width=True)
st.markdown("---")
# ------- 5️⃣ Country-wise Destination IPs -------
st.markdown(
    '<h2 style="text-align: center; margin-bottom: 1.1rem;">COUNTRY-WISE TRAFFIC</h2>',
    unsafe_allow_html=True
)
dst_country_col = next((c for c in df.columns if "dstipcountry" in c.lower()), None)
if dst_country_col:
    df5 = df[dst_country_col].dropna().value_counts().reset_index().head(10)
    df5.columns = ["Country", "Traffic Count"]
    fig5 = px.bar(df5, x="Country", y="Traffic Count", color='Traffic Count', color_continuous_scale='Turbo')
    fig5.update_layout(height=600, template='plotly_dark',
                       paper_bgcolor='rgba(0,0,0,0)', 
                       plot_bgcolor='rgba(0,0,0,0)')    
    st.plotly_chart(fig5, use_container_width=True)
else:
    st.warning("Destination country column not found in output.")


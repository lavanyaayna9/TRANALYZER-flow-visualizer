import streamlit as st
import pandas as pd
import socket
import whois
from ipwhois import IPWhois
import dns.resolver
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import re

def render_box(title, data_dict):
    st.markdown(f"""
<div style="background: rgba(255,255,255,0.08);
            border-radius: 10px;
            padding: 1rem 1.2rem;
            text-align: left;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            animation: fadeInSlide 1s ease;">
    <h5 style="color:#ffb6c1;">{title}</h5>
    <ul style="list-style-type: none; padding-left: 0; margin: 0;">
        {''.join(f'<li><b>{k}:</b> {v}</li>' for k,v in data_dict.items())}
    </ul>
</div>
""", unsafe_allow_html=True)
def find_similar_domains(domain):
    api_key = "d544afe4627896cc3ae4a83561b924711eef9c0e"
    headers = {
        "X-API-KEY": api_key,
        "Content-Type": "application/json"
    }
    query = f"sites similar to {domain}"
    response = requests.post(
        "https://google.serper.dev/search",
        headers=headers,
        json={"q": query}
    )
    try:
        results = response.json().get("organic", [])
        domains = []
        for r in results[:6]:
            url = r.get("link", "")
            if "://" in url:
                parts = url.split("/")
                d = parts[2].replace("www.", "")
                domains.append(d)
        return list(dict.fromkeys(domains))
    except Exception:
        return []

def render_similar_domains_card(domains):
    if not domains:
        st.info("No similar domains found.")
        return

    st.markdown("SIMILAR DOMAINS")
    cols = st.columns(len(domains))
    for col, domain in zip(cols, domains):
        logo_url = f"https://logo.clearbit.com/{domain}"
        with col:
            st.markdown(f"""
                <div style="background: rgba(255,255,255,0.05);
                            padding: 1rem;
                            border-radius: 12px;
                            text-align: center;
                            box-shadow: 0 2px 8px rgba(0,0,0,0.25);
                            animation: fadeInSlide 0.8s ease-out;">
                    <img src="{logo_url}" onerror="this.style.display='none'" width="64" style="margin-bottom: 0.6rem;" />
                    <div style="font-weight: 600; font-size: 1rem; color: #58a6ff;">
                        <a href="https://{domain}" target="_blank" style="text-decoration:none; color:inherit;">
                            {domain}
                        </a>
                    </div>
                    <div style="font-size: 0.82rem; opacity: 0.7;">Global rank: N/A</div>
                    <div style="font-size: 0.82rem; opacity: 0.7;">Daily Visitors: N/A</div>
                </div>
            """, unsafe_allow_html=True)
def get_global_rank(domain):
    api_key = "d544afe4627896cc3ae4a83561b924711eef9c0e"
    headers = {
        "X-API-KEY": api_key,
        "Content-Type": "application/json"
    }
    query = f"site:similarweb.com {domain} global rank"
    url = "https://google.serper.dev/search"

    try:
        response = requests.post(url, headers=headers, json={"q": query})
        if response.status_code == 200:
            results = response.json().get("organic", [])
            for r in results:
                text = (r.get("title", "") + " " + r.get("snippet", "")).lower()
                match = re.search(r'global rank[^\d#]*(#?[\d,]+)', text)
                if match:
                    raw = match.group(1).replace(",", "").replace("#", "")
                    return int(raw)
        else:
            print("Serper error:", response.status_code, response.text)
    except Exception as e:
        print("Rank fetch error:", e)

# -------------------- PAGE CONFIG --------------------
st.set_page_config(page_title="Domain + IP Lookup", layout="wide")

st.markdown("""
<style>
html, body, .stApp {
    background: linear-gradient(90deg, #331C33 0%, #2D1A70 50%, #2D1C33 100%);
    color: #FFFFFF;
    text-align: center;
    font-family: 'Poppins', 'Segoe UI', sans-serif;
}
label, .stTextInput > label {
    color: white !important;
    font-weight: 600;
}
h1, h2, h3 {
    text-shadow: 0 2px 8px #00000088;
}
.scrollable-table-wrapper {
    max-height: 420px;
    overflow-y: auto;
    border-radius: 15px;
    box-shadow: 0 2px 12px rgba(20,20,40,0.24);
    margin-bottom: 22px;
}
.scrollable-table-wrapper::-webkit-scrollbar {
    width: 8px;
    background: #24243e;
}
.scrollable-table-wrapper::-webkit-scrollbar-thumb {
    background: #302b63;
    border-radius: 7px;
}
.custom-gradient-table th {
    background: transparent;
    color: #fff;
    font-size: 22px;
    padding: 6px 10px;
    text-align: center;
}
.custom-gradient-table td {
    background: transparent;
    color: #fff;
    padding: 5px 10px;
    border-bottom: 1px solid rgba(200,200,255,0.08);
    font-size: 20px;
    text-align: center;
}
.ip-table th, .ip-table td {
    color: #fff;
    background: transparent;
    font-size: 2.13rem;
    padding: 7px 11px;
    border: none;
    text-align: center;
}
@keyframes fadeInSlide {
    0%   { opacity: 0; transform: translateY(30px);}
    100% { opacity: 1; transform: translateY(0);}
}
</style>
""", unsafe_allow_html=True)

# -------------------- UTILITIES --------------------
def safe_date(d):
    if isinstance(d, list):
        d = d[0]
    return d.strftime("%Y-%m-%d %H:%M:%S") if isinstance(d, datetime) else str(d)

def get_meta_description(domain):
    try:
        if not domain.startswith("http"):
            domain = "https://" + domain
        resp = requests.get(domain, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        desc = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
        return desc["content"].strip() if desc and desc.get("content") else "No description available."
    except Exception:
        return "Description could not be fetched."

def get_domain_logo(domain):
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    return f"https://logo.clearbit.com/{domain}"

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        ip = socket.gethostbyname(domain)
        ip_info = IPWhois(ip).lookup_rdap()
        dns_records = dns.resolver.resolve(domain, 'A')
        dns_list = [r.to_text() for r in dns_records]
        subdomains = [f"www.{domain}", f"mail.{domain}", f"ftp.{domain}"]

        return {
            "ADDRESSING DETAILS": {
                "Hosting Company": ip_info.get("network", {}).get("name", "N/A"),
                "IPs": [ip],
                "DNS": dns_list,
                "Subdomains": subdomains
            },
            "IP DETAILS": {
                "NetRange": f"{ip_info.get('network', {}).get('start_address', '')} - {ip_info.get('network', {}).get('end_address', '')}",
                "CIDR": ip_info.get("network", {}).get("cidr", ""),
                "NetName": ip_info.get("network", {}).get("name", ""),
                "NetHandle": ip_info.get("network", {}).get("handle", ""),
                "Parent": ip_info.get("network", {}).get("parent_handle", ""),
                "NetType": ip_info.get("network", {}).get("type", ""),
                "OriginAS": ip_info.get("asn", ""),
                "Organization": ip_info.get("network", {}).get("org_ref", {}).get("name", "N/A")
            },
            "OWNERSHIP": {
                "Created": safe_date(w.creation_date),
                "Expires": safe_date(w.expiration_date),
                "Owner": w.name,
                "Registrar": w.registrar,
                "Owner Emails": w.emails
            },
            "WHOIS INFORMATION": {
                "Domain Name": w.domain_name,
                "Registry Domain ID": w.registry_id,
                "Registrar WHOIS Server": w.whois_server,
                "Registrar URL": w.referral_url,
                "Updated Date": safe_date(w.updated_date),
                "Creation Date": safe_date(w.creation_date),
                "Registrar Expiration": safe_date(w.expiration_date),
                "Registrar": w.registrar
            }
        }

    except Exception as e:
        return {"error": str(e)}

# -------------------- DOMAIN LOOKUP SECTION --------------------
st.markdown("""
<h1 style="font-size: 2.7rem; text-align: center; margin-bottom: 1.5rem;">
DOMAIN INSIGHTS
</h1>
""", unsafe_allow_html=True)

domain = st.text_input("Enter a domain to inspect", "")
if domain.strip():
    with st.spinner("Fetching domain data..."):
        info = get_domain_info(domain)

    if "error" in info:
        st.error(f"❌ Error: {info['error']}")
    else:
        about_text = get_meta_description(domain)
        logo_url = get_domain_logo(domain)
        rank = get_global_rank(domain)

        # -------- Heading --------
        st.markdown("""
<h2 style="
    font-size: 2.2rem;
    margin-bottom: 0.5rem;
    text-align: left;
">ABOUT THIS DOMAIN
</h2>
""", unsafe_allow_html=True)

        # -------- About Paragraph + Logo --------
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown(f"""
<div style="
    width: 100%;
    max-width: 750px;
    padding: 1.25rem 1.5rem;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(88,166,255,0.1), rgba(88,166,255,0.03));
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    text-align: left;
    font-size: 1.15rem;
    line-height: 1.65;
    border-left: 5px solid #ffffff;
    margin-top: 0;
    margin-bottom: 1.2rem;
    animation: fadeInSlide 1s ease-out;
">
  {about_text}
</div>
""", unsafe_allow_html=True)

            if rank:
                st.markdown(f"""
        <div style="margin-top: 0px;
                    background: rgba(255, 255, 255, 0.07);
                    border-left: 5px solid #ffffff;
                    padding: 0.8rem 1.2rem;
                    border-radius: 10px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                    font-size: 1.05rem;
                    font-weight: 500;
                    text-align: center;
                    max-width: 200px;
                    animation: fadeInSlide 0.6s ease;">
            GLOBAL RANK:<br><span style="color: #ffd700;">#{rank:,}</span>
        </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
        <div style="font-size: 0.85rem; color: gray; margin-top: 0.6rem; text-align: center;">
            GLOBAL RANK: <i>Not available</i>
        </div>
                """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
    <div style="margin-top: -40px; text-align: center;">
        <img src="{logo_url}" width="150" style="border-radius: 12px;" />
        <div style="margin-top: 8px; font-size: 0.9rem; color: #ccc;">{domain}</div>
    </div>
    """, unsafe_allow_html=True)

        st.markdown("<hr style='border: 1px solid #555;'>", unsafe_allow_html=True)

        # -------- Row 1: Address + Ownership --------
        row1_col1, row1_col2 = st.columns(2)
        with row1_col1:
            render_box("ADDRESSING DETAILS", info["ADDRESSING DETAILS"])
        with row1_col2:
            render_box("OWNERSHIP", info["OWNERSHIP"])

        st.markdown("<div style='margin-bottom: 24px;'></div>", unsafe_allow_html=True)

        # -------- Row 2: IP Details + WHOIS Info --------
        row2_col1, row2_col2 = st.columns(2)
        with row2_col1:
            render_box("IP DETAILS", info["IP DETAILS"])
        with row2_col2:
            render_box("WHOIS INFORMATION", info["WHOIS INFORMATION"])

        st.markdown("<div style='margin-bottom: 24px;'></div>", unsafe_allow_html=True)

        # -------- Similar Domains --------
        similar_domains = find_similar_domains(domain)
        render_similar_domains_card(similar_domains)

# -------------------- IP LOOKUP SECTION --------------------
st.markdown("<hr style='border-top: 3px dashed #666; margin-top: 60px;'>", unsafe_allow_html=True)
st.markdown("<h1 style='text-align:center;'>IP LOOKUP</h1>", unsafe_allow_html=True)

ip_input = st.text_input("Enter an IP address to look up", key="ip_lookup_input", placeholder="e.g. 8.8.8.8")

if ip_input:
    with st.spinner(f"Looking up {ip_input.strip()}..."):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_input.strip()}/json")
            if response.status_code == 200:
                data = response.json()
                display_data = {
                    key.replace("_", " ").title(): val
                    for key, val in data.items()
                }

                col_ip, col_map = st.columns([1.2, 2])

                with col_ip:
                    render_box("IP INFORMATION", display_data)

                with col_map:
                    loc = data.get("loc")
                    if loc:
                        try:
                            lat, lon = map(float, loc.split(","))
                            st.map(data=[{"lat": lat, "lon": lon}], zoom=6, height=380)
                        except Exception:
                            st.warning("Could not parse location data.")
                    else:
                        st.info("No location data found for this IP.")
            else:
                st.error(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            st.error(f"An error occurred: {e}")

TRANALYZER FLOW VISUALIZER With IP & Domain Lookup

FEATURES:
1.Upload and analyze .pcap files using Tranalyzer2

2.Visual dashboards for protocols, top IPs, and geolocation

3.Domain & IP intelligence (WHOIS, DNS, ASN, geo info)

4.Clean responsive UI using Streamlit

INSTALLATION GUIDE

1. Clone the Repository
git clone https://github.com/lavanyaayna9/TRANALYZER-flow-visualizer.git

2. Setup Tranalyzer2 (one-time)

Navigate to your Tranalyzer directory:
cd tranalyzer2-0.9.3

Run setup:
./setup.sh
source ~/.bashrc

Install system dependencies:
sudo apt-get install autoconf autoconf-archive automake libbsd-dev libpcap-dev libreadline-dev libtool make meson zlib1g-dev

Set and confirm your T2 path:
export T2HOME="$PWD"
echo $T2HOME

Build all plugins:
t2build -a

If any plugin fails, build it individually:
t2build <plugin-name>

Ensure the following plugins are built:
basicFlow

basicStats

protoStats

connStat

descriptiveStats

dnsDecode

geoip

nDPI

portClassifier

sslDecode

tcpFlags

tcpStates

pktSIATHisto

txtSink

List built plugins:
t2build -l
Test your setup:
t2 -r sample_file.pcap
You should see an analysis output. If not, refer to: https://tranalyzer.com/tutorial/installation

3. Run the Flow Visualizer

Activate virtual env: source t2flow-env/bin/activate

Step 1: Find Tranalyzer Path
From your project root, run:
find . -type f -name "tranalyzer"
Copy the full path it returns — e.g.:
/home/youruser/tranalyzer2-0.9.3/tranalyzer2/build/tranalyzer

Step 2: Install Python dependencies
Navigate to your project folder and install:
cd project
pip install -r requirements.txt

Step 3: Configure your Tranalyzer path
Edit the path used in the upload script:
cd pages
nano 1_Upload_pcap.py
Replace the value of t2_path with your copied Tranalyzer path.
Save & exit:
Press Ctrl + O → Enter (to save)
Press Ctrl + X (to exit)

Step 4: Launch the App
Go back to project directory and run:

cd ..
streamlit run Home.py

Visit http://localhost:8501 in your browser.




TRANALYZER FLOW VISUALIZER WITH IP/DOMAIN LOOK UP
--------------------------------------------------
INSTALLATION STEPS:
1. Clone this repository.
2. Commands to run one by one:
cd tranalyzer2-0.9.3
./setup.sh
source ~/.bashrc
sudo apt-get install autoconf autoconf-archive automake libbsd-dev libpcap-dev libreadline-dev libtool make meson zlib1g-dev
T2HOME="$PWD"
echo $T2HOME
t2build -a
3. This will enable all the plugins by default.
4. If a plugin is not built or gives error, just built it using : t2build nameoftheplugin
5. Make sure the following plugins are succesfully built:
basicFlow
basicStats
protoStats
connStat
descriptiveStats
dnsDecode
geoip
nDPI
portClassifier
protoStats
sslDecode
tcpFlags
tcpStates
pktSIATHisto
txtSink
6. Check the plugins that are build using t2build -l. This will provide u with a list of the plugins that are built.
7. Verify by running any pcap file using: t2 -r nameoffile.pcap
8. Output must appear.
9. 
mysqlSink 


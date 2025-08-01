extract-samples.sh
------------------

This script extract sent samples from the following antiviruses:
Avira, AVG and Avast

httpSniffer config:
#define HTTP_SAVE_PUNK    1
#define HTTP_PUNK_AV_ONLY 1 // only extract antivirus related files
                            // leave to 0 to extract all HTTP files with unknown mime type

Usage:
    extract-samples.sh -o OUTPUT_DIR [OPTION...] <FLOW_FILE>

Optional arguments:
    -o DIR        directory where malware samples are extracted
    -p DIR        httpSniffer punk directorty (default: /tmp/httpPunk)
    -h, --help    show this help, then exit


antivirus-id.sh
---------------

This script extract unique client/update ID from the following antiviruses:
Avira, AVG, Avast and ESET

The duplicate ID mode (-d) allows to track clients with dynamic IPs

httpSniffer config:
#define HTTP_AVAST_CID 1
#define HTTP_ESET_UID  1

Usage:
    antivirus-id.sh [OPTION...] <FLOW_FILE>

Optional arguments:
    -g            output GeoIP information
    -d            only output IDs associated with multiple IPs
    -h, --help    show this help, then exit

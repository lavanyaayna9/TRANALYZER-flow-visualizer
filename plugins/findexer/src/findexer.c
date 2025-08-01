// Copyright (c) 2008-2022 Tranalyzer Development Team
// SPDX-License-Identifier: AGPL-3.0-only

// global includes
#include <stdio.h>
#include <stdbool.h>
#ifndef __APPLE__
#include <byteswap.h>
#else // __APPLE__
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#endif // __APPLE__
#include <unistd.h>

// local includes
#include "findexer.h"
#include "t2Plugin.h"
#include "memdebug.h"

// data types

typedef enum {
    OUTPUT_FLOWS,     // _flows.xer output
    OUTPUT_PKTS,      // _packets.xer output
} OutputType;

// per PCAP header in _flows.xer / _packets.xer files
typedef struct {
    uint64_t pos;              // pos of this pcap hdr in output file
    union {
        uint64_t flow_count;   // number of findexerFlow_t in _flows.xer
        uint64_t first_pkt;    // 1st pkt number in PCAP (_packets.xer)
    };
    union {
        uint64_t flow_ptr_pos; // pos in file where to write pointer to next findexerFlow_t
        uint64_t last_pkt;     // last pkt number in PCAP (_packets.xer)
    };
} pcap_hdr_t;

// _flows.xer or _packets.xer output
typedef struct {
    FILE* file;
    OutputType type;           // _flows.xer or _packets.xer
    uint32_t pcap_count;       // number of pcap_hdr_t in file
    pcap_hdr_t pcap_hdr;       // current findexer PCAP header
#if FNDXR_SPLIT == 1
    uint64_t index;
    char* index_pos;           // points to the numerical part of the filename
    // Num. of terminated flows in current output file. This is different from flowCount as a flow packet
    // indices can be split in multiple output files in case it spans across multiple input PCAPs.
    uint64_t terminated_flow_count;
#endif // FNDXR_SPLIT
    char filename[PATH_MAX];
} findexer_output_t;

// pcap types
typedef enum {
    PCAP_UNKNOWN, // unknown type of PCAP
    PCAP_SE,      // standard PCAP system endianness
    PCAP_OE,      // standard PCAP opposite endianness (currently not implemented in t2)
    PCAPNG_SE,    // PcapNg system endianness
    PCAPNG_OE,    // PcapNg opposite endianness (currently not implemented in t2)
} PcapType;

typedef struct {
    uint64_t pos;              // current packet position in PCAP
    uint64_t bytes_processed;  // used to compute next position
    uint64_t num_pkts;         // used to compute next position
    uint64_t pcap_size;        // used to compute next position
    int64_t index;             // PCAP index (t2 -R | -D)
    bool skip;                 // skip current PCAP (unsupported format)
    char filename[PATH_MAX];
} pcap_input_t;

// Global variables

// plugin global variables
static findexerFlow_t* findexer_flows;
static bool enabled = true;

static pcap_input_t pcap_input = { .index = -1 };

static findexer_output_t flows_output = { .type = OUTPUT_FLOWS };
#if FNDXR_SPLIT == 1
static uint64_t file_frag_size;
#endif // FNDXR_SPLIT

// queue of open flows in current PCAP (will be written before switching to next pcap)
TAILQ_HEAD(flow_queue_s, findexerFlow_s) opened_flows;

// packet mode: _packets.xer
static bool packet_mode = false;
static findexer_output_t pkts_output = { .type = OUTPUT_PKTS };
static list_uint64_t pkt_buffer;


// Tranalyzer functions

T2_PLUGIN_INIT("findexer", "0.9.3", 0, 9);


// helper functions

/**
 * Get PCAP type. Use already opened file by libpcap to avoid being unable to open file if
 * application is out of file descriptor (often happen with httpSniffer extraction).
 */
PcapType pcap_type() {
    #define PCAP_MAGIC    0xa1b2c3d4
    #define PCAP_MAGIC_NS 0xa1b23c4d
    #define PCAPNG_HEADER 0x0a0d0d0a
    #define PCAPNG_MAGIC  0x1a2b3c4d

    // NOTE: this libpcap function does not work on Windows
    FILE *f = pcap_file(captureDescriptor);
    if (!f) {
#if VERBOSE > 0
        T2_PWRN(plugin_name, "invalid PCAP file stream");
#endif
        return PCAP_UNKNOWN;
    }

    // backup position in file and rewind to first byte
    const off_t current_pos = ftello(f);
    if (fseeko(f, 0, SEEK_SET) != 0) {
#if VERBOSE > 0
        T2_PWRN(plugin_name, "failed to seek to start of PCAP");
#endif
        return PCAP_UNKNOWN;
    }

    // read first 12 bytes of PCAP file
    uint32_t buffer[3];
    if (fread(buffer, sizeof(buffer[0]), 3, f) != 3) {
#if VERBOSE > 0
        T2_PWRN(plugin_name, "failed to read PCAP header");
#endif
        fseeko(f, current_pos, SEEK_SET);
        return PCAP_UNKNOWN;
    }

    // seek back to position at the start of this function
    if (fseeko(f, current_pos, SEEK_SET) != 0) {
#if VERBOSE > 0
        T2_PWRN(plugin_name, "failed to seek back to original position in PCAP");
#endif
        return PCAP_UNKNOWN;
    }

    // check the different types of known PCAPs
    if (buffer[0] == PCAP_MAGIC || buffer[0] == PCAP_MAGIC_NS) {
        return PCAP_SE;
    } else if (buffer[0] == bswap_32(PCAP_MAGIC) ||
               buffer[0] == bswap_32(PCAP_MAGIC_NS))
    {
        return PCAP_OE;
    } else if (buffer[0] == PCAPNG_HEADER) {
        if (buffer[2] == PCAPNG_MAGIC) {
            return PCAPNG_SE;
        } else if (buffer[2] == bswap_32(PCAPNG_MAGIC)) {
            return PCAPNG_OE;
        }
    }
    return PCAP_UNKNOWN;
}

/**
 * Get current PCAP index
 */
static int64_t current_pcap_index() {
    switch (capType & CAPTYPE_REQUIRED) {
        case CAPFILE: // -r
            return 1;
        case LISTFILE: // -R
            return (int64_t)caplist_index;
        case DIRFILE: // -D
            return (int64_t)fileNum;
        default:
#if VERBOSE > 0
            T2_PWRN(plugin_name, "mix of several capture types: capType = 0x%04" B2T_PRIX16, capType);
            T2_PWRN(plugin_name, "plugin got disabled");
#endif
            enabled = false; // disable plugin to avoid avalanche of warnings
            return -1;
    }
}

/**
 * Get currently processed PCAP full path. Returns false on error.
 * This function assumes that pcap_path is at least PATH_MAX bytes long.
 */
static bool pcap_full_path(char* pcap_path) {
    char *path = NULL;
    switch (capType & CAPTYPE_REQUIRED) {
        case CAPFILE: // -r
            path = capName;
            break;
        case LISTFILE: // -R
            path = caplist_elem->name;
            break;
        case DIRFILE: // -D
            path = globFName;
            break;
        default:
#if VERBOSE > 0
            T2_PWRN(plugin_name, "mix of several capture types: capType = 0x%04" B2T_PRIX16, capType);
#endif
            return false;
    }
    // useless memset but otherwise valgrind complains
    memset(pcap_path, 0, PATH_MAX);
    // dereference symlinks and get absolute path of PCAP
    if (realpath(path, pcap_path) != pcap_path) {
        T2_PERR(plugin_name, "failed to find real path of PCAP file.");
        return false;
    }
    return true;
}

/**
 * Write the findexer header to file.
 */
static bool write_findexer_hdr(findexer_output_t *output) {
    const uint64_t magic = output->type == OUTPUT_FLOWS ? FINDEXER_MAGIC : PKTSXER_MAGIC;
    if (fwrite(&magic, sizeof(magic), 1, output->file) != 1) {
        return false;
    }
    output->pcap_count = 0;
    if (fwrite(&output->pcap_count, sizeof(output->pcap_count), 1, output->file) != 1) {
        return false;
    }
    const uint64_t first_pcap = 0;
    if (fwrite(&first_pcap, sizeof(first_pcap), 1, output->file) != 1) {
        return false;
    }
    // where pointer to next pcap_hdr will be written
    output->pcap_hdr.pos = sizeof(magic) + sizeof(output->pcap_count);
    return true;
}

/**
 * Write a findexer PCAP header to file.
 */
static bool write_pcap_hdr(findexer_output_t *output, pcap_input_t *input) {
    // keep track of header start position
    const uint64_t pos = (uint64_t)ftello(output->file);
    // write next pcap pointer and keep track of it
    const uint64_t zero64 = 0;
    pcap_hdr_t *hdr = &output->pcap_hdr;
    if (fwrite(&zero64, sizeof(zero64), 1, output->file) != 1) {
        return false;
    }
    if (output->type == OUTPUT_FLOWS) {
        hdr->flow_count = 0;
    }
    // write 1st packet number / flow count
    if (fwrite(&hdr->flow_count, sizeof(&hdr->flow_count), 1, output->file) != 1) {
        return false;
    }
    // write last packet number / first flow pointer and keep track of it
    if (output->type == OUTPUT_FLOWS) {
        hdr->flow_ptr_pos = (uint64_t)ftello(output->file);
    }
    if (fwrite(&zero64, sizeof(zero64), 1, output->file) != 1) {
        return false;
    }
    // write the length of the pcapName as a uint16_t followed by the pcap name (similar to pascal strings)
    const size_t len = strlen(input->filename);
    if (len > USHRT_MAX) {
        T2_PERR(plugin_name, "PCAP path is longer than 2^16 bytes.");
        return false;
    }
    const uint16_t slen = (uint16_t)len;
    if (fwrite(&slen, sizeof(slen), 1, output->file) != 1) {
        return false;
    }
    if (fwrite(input->filename, sizeof(char), len, output->file) != len) {
        return false;
    }
    // link previous PCAP header to this one
    if (fseeko(output->file, hdr->pos, SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&pos, sizeof(pos), 1, output->file) != 1) {
        return false;
    }
    hdr->pos = pos;
    // increment PCAP count in findexer header
    output->pcap_count++;
    if (fseeko(output->file, sizeof(uint64_t), SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&output->pcap_count, sizeof(output->pcap_count), 1, output->file) != 1) {
        return false;
    }
    // go back to end of file
    if (fseeko(output->file, 0, SEEK_END) != 0) {
        return false;
    }
    return true;
}

/**
 * Write flow header with all its packets positions.
 */
static bool flow_hdr_write(findexer_output_t *output, findexerFlow_t* const flow) {
    if (pcap_input.skip) {
        return true;
    }
    // keep track of header start position
    const uint64_t pos = (uint64_t)ftello(output->file);
    // write NULL next flow header pointer
    const uint64_t nextFlowHeader = 0;
    if (fwrite(&nextFlowHeader, sizeof(nextFlowHeader), 1, output->file) != 1) {
        return false;
    }
    // write flow index
    const flow_t * const flowP = &flows[flow->flow_index];
    const uint64_t findex = flowP->findex;
    if (fwrite(&findex, sizeof(findex), 1, output->file) != 1) {
        return false;
    }
    // set direction flag: we do it as late as possible in case a plugin changes
    // this value after the flow creation.
    uint8_t flags = flow->flags;
    if (FLOW_IS_B(flowP)) {
        flags |= TO_BITMASK(REVERSE_FLOW);
    }
    // write flags
    if (fwrite(&flags, sizeof(flags), 1, output->file) != 1) {
        return false;
    }
    // write the number of packets in this flow
    if (fwrite(&flow->pkt_pos.size, sizeof(flow->pkt_pos.size), 1, output->file) != 1) {
        return false;
    }
    if (flow->pkt_pos.size != 0) {
        // write the packet positions
        if (fwrite(flow->pkt_pos.data, sizeof(*flow->pkt_pos.data), flow->pkt_pos.size, output->file) != flow->pkt_pos.size) {
            return false;
        }
    }
    pcap_hdr_t *phdr = &output->pcap_hdr;
    // link previous flow header to this one
    if (fseeko(output->file, phdr->flow_ptr_pos, SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&pos, sizeof(pos), 1, output->file) != 1) {
        return false;
    }
    phdr->flow_ptr_pos = pos;
    // increment flow count in PCAP header
    phdr->flow_count++;
    if (fseeko(output->file, phdr->pos + sizeof(uint64_t), SEEK_SET) != 0) {
        return false;
    }
    if (fwrite(&phdr->flow_count, sizeof(phdr->flow_count), 1, output->file) != 1) {
        return false;
    }
    // go back to end of file
    if (fseeko(output->file, 0, SEEK_END) != 0) {
        return false;
    }

    return true;
}

static bool list_init(list_uint64_t *list, size_t initial_size) {
    if (!(list->data = t2_calloc(initial_size, sizeof(*list->data)))) {
        return false;
    }
    list->allocated = initial_size;
    list->size = 0;
    return true;
}

static void list_delete(list_uint64_t *list) {
    free(list->data);
    list->data = NULL;
    list->size = 0;
    list->allocated = 0;
}

static bool list_append(list_uint64_t *list, uint64_t elem) {
    // realloc memory if not enough space to store current element
    if (list->size >= list->allocated) {
        list->allocated *= 2;
        uint64_t* tmp = t2_realloc(list->data, list->allocated * sizeof(*list->data));
        if (!tmp) {
            free(list->data);
            return false;
        }
        list->data = tmp;
    }

    // append current element
    list->data[list->size++] = elem;

    return true;
}

/**
 * Initialize default values for findexerFlow_t structure
 */
static bool flow_hdr_init(unsigned long flow_index) {
    findexerFlow_t* const flow = &findexer_flows[flow_index];
    memset(flow, 0, sizeof(*flow)); // set everything to 0
    // store flow index
    flow->flow_index = flow_index;
    // initialize list of packet positions
    if (!list_init(&flow->pkt_pos, FINDEXER_INITIAL_PACKET_ALLOC)) {
        return false;
    }
    // flag flow as first appearing in current .xer, will be removed on first write
    flow->flags |= TO_BITMASK(FIRST_XER);
    // append to open flows queue
    TAILQ_INSERT_TAIL(&opened_flows, flow, entries);

    return true;
}

static bool write_pkt_buffer(findexer_output_t *output, list_uint64_t *buffer) {
    // write the packet positions
    if (buffer->size != 0) {
        if (fwrite(buffer->data, sizeof(*buffer->data), buffer->size, output->file) != buffer->size) {
            return false;
        }
    }
    buffer->size = 0;
    return true;
}

/**
 * Write all the open flows in queue to the _flows.xer file
 * Or write all remaining packet positions to the _packets.xer file
 */
static bool flush_output_data(findexer_output_t *output) {
    if (output->type == OUTPUT_FLOWS) {
        // for each flow in queue
        findexerFlow_t* flow;
        TAILQ_FOREACH(flow, &opened_flows, entries) {
            // write flow header
            if (!flow_hdr_write(output, flow)) {
                return false;
            }
            // update flags (remove FIRST_XER bit)
            flow->flags &= ~TO_BITMASK(FIRST_XER);
            // reset the number of stored packet positions
            flow->pkt_pos.size = 0;
        }
    } else if (output->type == OUTPUT_PKTS) {
        pcap_hdr_t *ph = &output->pcap_hdr;
        // write 1st packet number
        if (fseeko(output->file, ph->pos + sizeof(uint64_t), SEEK_SET) != 0) {
            return false;
        }
        if (fwrite(&ph->first_pkt, sizeof(ph->first_pkt), 1, output->file) != 1) {
            return false;
        }
        // write last packet number
        if (fwrite(&ph->last_pkt, sizeof(ph->last_pkt), 1, output->file) != 1) {
            return false;
        }
        // go back to end of file
        if (fseeko(output->file, 0, SEEK_END) != 0) {
            return false;
        }
        // write the packet positions
        if (!write_pkt_buffer(output, &pkt_buffer)) {
            return false;
        }
        // reset 1st and last packet number
        ph->first_pkt = 0;
        ph->last_pkt = 0;
    } else {
        T2_PERR(plugin_name, "unsupported output type");
        return false;
    }
    return true;
}

/**
 * Update packet position to the end of current packet.
 * Write current pcap flow index and pcap header and switch to next pcap if the pcap has
 * changed.
 */
static bool update_pos_and_pcap(pcap_input_t *input, uint64_t pcap_pkt_len) {
    // keep track of number of processed packet before update
    const uint64_t last_num_pkts = input->num_pkts;
    if (!input->skip) {
        // update packet position since last call
        if (input->num_pkts != numPackets) {
            const uint64_t pkt_count = numPackets - input->num_pkts;
            const uint64_t byte_count = bytesProcessed - input->bytes_processed;
            input->pos += byte_count + 16 * pkt_count;
            input->num_pkts = numPackets;
            input->bytes_processed = bytesProcessed;
        }
    }

    // don't switch pcap if the pcap hasn't changed
    const int64_t new_index = current_pcap_index();
    if (new_index == input->index) {
        return true;
    }
    // if this isn't the first pcap, write all previous packets positions
    if (input->index != -1 && !input->skip) {
        if (!flush_output_data(&flows_output)) {
            T2_PERR(plugin_name, "failed to write previous PCAP open flows. Disk full?");
            return false;
        }
        if (packet_mode && !flush_output_data(&pkts_output)) {
            T2_PERR(plugin_name, "failed to write packet positions. Disk full?");
            return false;
        }
    }

    // update the packet position (to the end of current packet)
    if (input->num_pkts == last_num_pkts + 1 || input->skip) {
        // if only one packet has been processed since last PCAP switch,
        // we can safely assume that it start just after PCAP header.
        // if the last PCAP was in an unsupported format (e.g. PcapNg), we
        // also cannot rely on bytes processed and have to assume that this
        // is the first packet of a newly supported PCAP.
        input->pos = 24 + pcap_pkt_len; // 24 = size of pcap file header
        input->num_pkts = numPackets;
        input->bytes_processed = bytesProcessed;
    } else {
        // otherwise, we have to assume that last PCAP was not cut and the sum of its
        // processed packets bytes + headers sizes match the size of the file
        input->pos = 24 + input->pos - input->pcap_size; // 24 = size of pcap file header
    }
    // WARNING: the packet position will be wrong if the last PCAP was cut in the middle of a packet
    // and the current PCAP first packet did not call t2OnLayer2(). This means that all
    // computed indexes for current PCAP will be wrong.

    input->index = new_index;

    // get current PCAP path
    if (!pcap_full_path(input->filename)) {
        T2_PERR(plugin_name, "failed to get current PCAP path.");
        return false;
    }

    // check if this is a PCAP format supported by findexer
    PcapType type = pcap_type();
    if (type != PCAP_SE && type != PCAP_OE) {
#if VERBOSE > 0
        const char *format = "";
        if (type == PCAPNG_SE || type == PCAPNG_OE) {
            format = "PcapNg ";
        }
        T2_PWRN(plugin_name, "plugin disabled for current PCAP: %sformat not supported", format);
#endif // VERBOSE > 0
        input->skip = true;
        return true;
    }
    input->skip = false;

    // write a new PCAP header in findexer file
    if (!write_pcap_hdr(&flows_output, input)) {
        T2_PERR(plugin_name, "failed to write PCAP header. Disk full?");
        return false;
    }
    if (packet_mode && !write_pcap_hdr(&pkts_output, input)) {
        T2_PERR(plugin_name, "failed to write PCAP header. Disk full?");
        return false;
    }
    // update the size of the newly opened pcap
    struct stat sb;
    if (stat(input->filename, &sb) == -1) {
        T2_PERR(plugin_name, "failed to stat PCAP file.");
        return false;
    }
    input->pcap_size = sb.st_size;
    return true;
}

#if FNDXR_SPLIT == 1
/**
 * If current output is bigger than the -W size, switch to next output, write findexer header and
 * rewrite current PCAP header.
 */
static bool switch_output_if_needed(findexer_output_t *output, pcap_input_t *input) {
    off_t size; // size of current output file (in #bytes or #flows)
    if (capType & WFINDEX) {
        size = output->terminated_flow_count;
    } else {
        size = ftello(output->file);
        if (size < 0) {
            T2_PERR(plugin_name, "failed to get file size");
            return false;
        }
    }
    // do not do anything if file size/flow limit is not reached
    if ((uint64_t)size < file_frag_size) {
        return true;
    }
    // write open flows, necessary so each open flow appear at least once in each XER file
    // to be able to back-track the start of a flow.
    if (!flush_output_data(output)) {
        T2_PERR(plugin_name, "failed to write previous PCAP open flows. Disk full?");
        return false;
    }
    // flush and close current findexer file
    fclose(output->file);
    // increase findexer file count and update number in filename
    output->index++;
    sprintf(output->index_pos, "%" PRIu64, output->index);
    // open new findexer output file
    if (!(output->file = fopen(output->filename, "wb"))) {
        T2_PERR(plugin_name, "failed to open findexer file");
        return false;
    }
    // write new findexer header
    if (!write_findexer_hdr(output)) {
        T2_PERR(plugin_name, "failed to write file header. Disk full?");
        return false;
    }
    // re-write header of currently opened PCAP
    if (!write_pcap_hdr(output, input)) {
        T2_PERR(plugin_name, "failed to write PCAP header. Disk full?");
        return false;
    }
    output->terminated_flow_count = 0;
    return true;
}
#endif // FNDXR_SPLIT

void create_output(findexer_output_t *output, const char * const suffix) {
    // check max filename length (including 20 digits for split output mode)
    const size_t suffix_size = strlen(suffix) + 1; // includes terminating '\0'
    const size_t blen = baseFileName_len;
    const size_t len = blen + suffix_size + 20;
    if (UNLIKELY(len > sizeof(output->filename))) {
        T2_PFATAL(plugin_name, "filename too long");
    }

    // create the finde.xer full path
    memcpy(output->filename, baseFileName, blen);
    memcpy(output->filename + blen, suffix, suffix_size);

    // if necessary, append count at the end of the file name
#if FNDXR_SPLIT == 1
    if (capType & OFILELN) {
        output->index = oFileNumB;
        output->index_pos = output->filename + strlen(output->filename);
        // append count
        sprintf(output->index_pos, "%" PRIu64, output->index);
    }
#endif // FNDXR_SPLIT

    // open findexer output file
    if (UNLIKELY(!(output->file = fopen(output->filename, "wb")))) {
        T2_PERR(plugin_name, "failed to open findexer file");
        free(findexer_flows);
        exit(EXIT_FAILURE);
    }

    // write the findexer header
    if (UNLIKELY(!write_findexer_hdr(output))) {
        T2_PERR(plugin_name, "failed to write file header. Disk full?");
        fclose(output->file);
        free(findexer_flows);
        exit(EXIT_FAILURE);
    }
}

static bool process_flow_packet(findexerFlow_t* flow, uint64_t position) {
    // check if packet was already parsed with the same flow index (SCTP with SCTP_STATFINDEX = 1)
    if (flow->pkt_pos.size > 0 && flow->pkt_pos.data[flow->pkt_pos.size - 1] == position) {
        return true;
    }

    if (!list_append(&flow->pkt_pos, position)) {
        T2_PERR(plugin_name, "failed to re-allocate memory for packet positions.");
        return false;
    }
    return true;
}

static bool process_packet_mode(list_uint64_t *buffer, pcap_hdr_t *hdr, uint64_t position) {
    if (buffer->size > 0 && buffer->data[buffer->size - 1] == position) {
        return true;
    }
    // write buffer to file if full
    if (buffer->size >= PKTSXER_BUFFER_SIZE) {
        // write the packet positions
        if (!write_pkt_buffer(&pkts_output, buffer)) {
            return false;
        }
    }
    if (!list_append(buffer, position)) {
        // should never happen
        T2_PERR(plugin_name, "failed to re-allocate memory for packet positions.");
        return false;
    }
    // update 1st and last packets
    if (hdr->first_pkt == 0) {
        hdr->first_pkt = numPackets;
    }
    hdr->last_pkt = numPackets;
    return true;
}


// Tranalyzer functions


void t2Init() {
    // disable plugin on live capture or if BPF is used
    if ((capType & IFACE) || bpfCommand) {
#if VERBOSE > 0
        T2_PWRN(plugin_name, "plugin disabled because of live capture or BPF");
#endif
        enabled = false;
        return;
    }

    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(findexer_flows);

    // initialize linked list of open flows
    TAILQ_INIT(&opened_flows);

#if FNDXR_SPLIT == 1
    file_frag_size = (uint64_t)oFragFsz;
#endif // FNDXR_SPLIT

    t2_env_t env[ENV_FNDXR_N] = {};

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_FNDXR_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(FNDXR_SUFFIX);
    T2_SET_ENV_STR(FNDXR_PKTSXER_SUFFIX);
#endif // ENVCNTRL > 0

    create_output(&flows_output, T2_ENV_VAL(FNDXR_SUFFIX));
    packet_mode = (capType & PKTFILE) != 0;
    if (packet_mode) {
        list_init(&pkt_buffer, PKTSXER_BUFFER_SIZE);
        create_output(&pkts_output, T2_ENV_VAL(FNDXR_PKTSXER_SUFFIX));
    }

#if ENVCNTRL > 0
    t2_free_env(ENV_FNDXR_N, env);
#endif // ENVCNTRL > 0
}

void t2OnNewFlow(packet_t* packet, unsigned long flow_index) {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    // update current packet position (end of packet)
    // create findexer pcap header if first packet of pcap
    const uint64_t pcap_pkt_len = packet->pcapHdrP->caplen + 16;
    if (!update_pos_and_pcap(&pcap_input, pcap_pkt_len)) {
        T2_PERR(plugin_name, "failed to update packet position and current PCAP");
        terminate();
    }
    // initialize tranalyzer flow structure
    if (!flow_hdr_init(flow_index)) {
        T2_PERR(plugin_name, "failed to allocate memory for packet positions.");
        terminate();
    }
}

/*
 * Do not delete this function. It is necessary in case there is no packet processed.
 * IPv4 PCAP in IPv6 mode for instance.
 */
void t2OnLayer2(packet_t* packet, unsigned long flow_index
#if ETH_ACTIVATE == 0
    UNUSED
#endif
) {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    // update current packet position (end of packet)
    // check if pcap has changed since last packet
    const uint64_t pcap_pkt_len = packet->pcapHdrP->caplen + 16;
    if (!update_pos_and_pcap(&pcap_input, pcap_pkt_len)) {
        T2_PERR(plugin_name, "failed to update packet position and current PCAP");
        terminate();
    }

#if ETH_ACTIVATE > 0
    if (pcap_input.skip || flow_index == HASHTABLE_ENTRY_NOT_FOUND) {
        return;
    }

    findexerFlow_t* flow = &findexer_flows[flow_index];
    const uint64_t position = pcap_input.pos - pcap_pkt_len;
    if (!process_flow_packet(flow, position)) {
        T2_PERR(plugin_name, "failed to process packet.");
        terminate();
    }
    if (packet_mode && !process_packet_mode(&pkt_buffer, &pkts_output.pcap_hdr, position)) {
        T2_PERR(plugin_name, "failed to process packet.");
        terminate();
    }
#endif // ETH_ACTIVATE > 0
}

void t2OnLayer4(packet_t* packet, unsigned long flow_index) {
    // don't do anything in live capture mode or if parsing a PcapNg
    if (!enabled || pcap_input.skip) {
        return;
    }
    findexerFlow_t* flow = &findexer_flows[flow_index];
    const uint64_t position = pcap_input.pos - packet->pcapHdrP->caplen - 16;
    if (!process_flow_packet(flow, position)) {
        T2_PERR(plugin_name, "failed to process packet.");
        terminate();
    }
    if (packet_mode && !process_packet_mode(&pkt_buffer, &pkts_output.pcap_hdr, position)) {
        T2_PERR(plugin_name, "failed to process packet.");
        terminate();
    }
}


void t2OnFlowTerminate(unsigned long flow_index, outputBuffer_t *buf UNUSED) {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }
    findexerFlow_t* flow = &findexer_flows[flow_index];
    // output only flows containing at least one packet in current PCAP
#if FNDXR_SPLIT == 1
    // switch to next findexer file if current one is full
    if (capType & OFILELN) {
        if (!switch_output_if_needed(&flows_output, &pcap_input)) {
            T2_PFATAL(plugin_name, "failed to switch output flow file.");
        }
        flows_output.terminated_flow_count++;
        if (packet_mode) {
            if (!switch_output_if_needed(&pkts_output, &pcap_input)) {
                T2_PFATAL(plugin_name, "failed to switch output packet file.");
            }
            pkts_output.terminated_flow_count++;
        }
    }
#endif // FNDXR_SPLIT
    // flow is terminated: this is the last .xer in which it will appear
    flow->flags |= TO_BITMASK(LAST_XER);
    // write the packet positions of this flow
    if (!flow_hdr_write(&flows_output, flow)) {
        T2_PFATAL(plugin_name, "failed to write flow header. Disk full?");
    }
    // free packet position list
    list_delete(&flow->pkt_pos);
    // remove flow from open flows queue
    TAILQ_REMOVE(&opened_flows, flow, entries);
}


void t2Finalize() {
    // don't do anything in live capture mode
    if (!enabled) {
        return;
    }

#if VERBOSE > 0
    if (!TAILQ_EMPTY(&opened_flows)) {
        T2_PWRN(plugin_name, "open flows not empty on application terminate.");
    }
#endif

    if (findexer_flows) {
        free(findexer_flows);
        findexer_flows = NULL;
    }

    struct stat file_status;

    // flush and close _flows.xer file
    if (flows_output.file) {
        fclose(flows_output.file);
    }
    // delete the file if empty
    if (stat(flows_output.filename, &file_status) == 0) {
        if (file_status.st_size == FINDEXER_MIN_HDRLEN) {
            unlink(flows_output.filename);
        }
    }

    if (packet_mode) {
        // flush and close _packets.xer file
        flush_output_data(&pkts_output);
        if (pkts_output.file) {
            fclose(pkts_output.file);
        }
        // delete the file if empty
        if (stat(pkts_output.filename, &file_status) == 0) {
            if (file_status.st_size == PKTSXER_MIN_HDRLEN) {
                unlink(pkts_output.filename);
            }
        }
        list_delete(&pkt_buffer);
    }
}

// vim: ts=4:sw=4:sts=4:expandtab

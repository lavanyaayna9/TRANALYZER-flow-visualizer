/*
 * liveXtr.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>     // for usleep

#include "liveXtr.h"
#include "t2Plugin.h"
#include "memdebug.h"

#if LIVEXTR_SPLIT != 0
#define LIVEXTR_SWITCH_PCAP 0xffffffffffffffff
#endif // LIVEXTR_SPLIT != 0


// Structs

struct main_rrbuffer {
    uint64_t start;
    uint64_t end;
#if LIVEXTR_MEMORY == 0
    FILE *file;
#else // LIVEXTR_MEMORY != 0
    uint8_t buffer[LIVEXTR_BUFSIZE];
#endif // LIVEXTR_MEMORY == 0
};


// Global variables

liveXtr_flow_t *liveXtr_flows;


// Static variables

static struct main_rrbuffer mainbuffer;
static uint64_t extracted_pkt_count = 0;
static struct offset_rrbuffer to_extract;
static char output_filename[PATH_MAX];

#if LIVEXTR_SPLIT != 0
static uint64_t filename_index;
static uint64_t file_frag_size;
static char *filename_num_pos; // points to the numerical part of the filename
static uint64_t terminated_flows = 0;
#endif // LIVEXTR_SPLIT != 0

static atomic_bool extract = true;
static pthread_t thread;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


// Tranalyzer function

T2_PLUGIN_INIT("liveXtr", "0.9.3", 0, 9);


// helper functions

/**
 * Place a new packet offset in the structure containing all valid packet offsets
 * for this flow. Automatically expend and re-arrange offsets when underlying
 * structure is full.
 *
 * @param buf     the structure containing the packet offsets of a given flow
 * @param offset  the new packet offset, in the main buffer/file, to add to this flow
 */
static void add_offset(struct offset_rrbuffer *buf, uint64_t offset) {
    // check if we need to increase allocated memory for packet offsets
    if (buf->last - buf->first >= buf->allocated) {
        // double allocated memory
        const uint64_t prev_allocated = buf->allocated;
        buf->allocated *= 2;
        uint64_t *tmp = realloc(buf->offsets, buf->allocated * sizeof(*tmp));
        if (!tmp) {
            T2_PERR(plugin_name, "failed to re-allocated memory for offset buffer");
            terminate();
        }
        buf->offsets = tmp;

        // move offsets so they are "round-robin contiguous" in the new buffer
        if (buf->first % prev_allocated != buf->first % buf->allocated) {
            // move what was after first element to the end of the buffer
            const uint64_t to_move = prev_allocated - (buf->first % prev_allocated);
            uint64_t *start = buf->offsets + prev_allocated - to_move;
            memcpy(start + prev_allocated, start, to_move * sizeof(*buf->offsets));
        } else if (buf->first % prev_allocated != 0) {
            // move what was before first in the newly allocated space
            const uint64_t to_move = buf->first % prev_allocated;
            memcpy(buf->offsets + prev_allocated, buf->offsets, to_move * sizeof(*buf->offsets));
        }
    }
    buf->offsets[buf->last % buf->allocated] = offset;
    ++buf->last;
}

/**
 * Removes from the per-flow RR buffer the packet offsets which have been overwritten
 * in the main file/buffer as they cannot be extracted anymore.
 *
 * @param buf    the structure containing the packet offsets of a given flow
 * @param start  the lowest packet offset, in the main buffer/file, which is not overwritten
 */
static void clean_overwritten(struct offset_rrbuffer *buf, uint64_t start) {
    while (buf->first < buf->last && buf->offsets[buf->first % buf->allocated] < start) {
        ++buf->first;
    }
}

#if LIVEXTR_MEMORY == 0

static bool read_chunk(struct main_rrbuffer *mainbuf, uint64_t offset, void *dest, uint64_t n) {
    if (fseeko(mainbuf->file, offset, SEEK_SET) != 0) {
        return false;
    }
    return fread(dest, 1, n, mainbuf->file) == n;
}

static bool write_chunk(struct main_rrbuffer *mainbuf, uint64_t offset, const void *src,
        uint64_t n) {
    if (fseeko(mainbuf->file, offset, SEEK_SET) != 0) {
        return false;
    }
    return fwrite(src, 1, n, mainbuf->file) == n;
}

#else // LIVEXTR_MEMORY != 0

static bool read_chunk(struct main_rrbuffer *mainbuf, uint64_t offset, void *dest, uint64_t n) {
    return memcpy(dest, &mainbuf->buffer[offset], n) == dest;
}

static bool write_chunk(struct main_rrbuffer *mainbuf, uint64_t offset, const void *src,
        uint64_t n) {
    void *const dest = &mainbuf->buffer[offset];
    return memcpy(dest, src, n) == dest;
}

#endif // LIVEXTR_MEMORY == 0

/**
 * Read n bytes from a specific offset of the main buffer. Takes care of the case where the
 * n bytes wrap around the end boundary of the buffer.
 */
static bool buf_read(struct main_rrbuffer *mainbuf, uint64_t offset, void *dest, uint64_t n) {
    if (n > LIVEXTR_BUFSIZE) {
        return false;
    }
    // check if the n bytes wrap around the end of the buffer
    offset %= LIVEXTR_BUFSIZE;
    if (offset + n > LIVEXTR_BUFSIZE) {
        const size_t len = LIVEXTR_BUFSIZE - offset;
        if (!read_chunk(mainbuf, offset, dest, len)) {
            return false;
        }
        dest += len;
        offset = 0;
        n -= len;
    }
    return read_chunk(mainbuf, offset, dest, n);
}

/**
 * Write n bytes at a specific offset of the main buffer. Takes care of the case where the
 * n bytes wrap around the end boundary of the buffer.
 */
static bool buf_write(struct main_rrbuffer *mainbuf, uint64_t offset, const void *src, uint64_t n) {
    if (n > LIVEXTR_BUFSIZE) {
        return false;
    }
    // check if the n bytes wrap around the end of the buffer
    offset %= LIVEXTR_BUFSIZE;
    if (offset + n > LIVEXTR_BUFSIZE) {
        const size_t len = LIVEXTR_BUFSIZE - offset;
        if (!write_chunk(mainbuf, offset, src, len)) {
            return false;
        }
        src += len;
        offset = 0;
        n -= len;
    }
    return write_chunk(mainbuf, offset, src, n);
}

/**
 * Append a new packet in the main memory buffer.
 * Returns the offset where it was placed.
 */
static uint64_t append_packet(struct main_rrbuffer *mainbuf,
                              const struct pcap_pkthdr *pkt_hdr,
                              const u_char *data,
                              uint32_t length) {
    if (pkt_hdr->caplen != length || length > LIVEXTR_MAX_PKT_SIZE) {
        T2_PERR(plugin_name, "data length does not match value in PCAP packet header");
        terminate();
    }
    // remove packets until there is enough space to store new one
    while (mainbuf->start + LIVEXTR_BUFSIZE - mainbuf->end < length + sizeof(*pkt_hdr)) {
        // read pcap header
        struct pcap_pkthdr to_remove_hdr;
        if (!buf_read(mainbuf, mainbuf->start, &to_remove_hdr, sizeof(to_remove_hdr))) {
            T2_PERR(plugin_name, "failed to read stored PCAP packet header");
            terminate();
        }
        // skip over pcap packet header and packet content
        mainbuf->start += sizeof(to_remove_hdr) + to_remove_hdr.caplen;
    }

    // copy the packet header+content into the buffer
    const uint64_t offset = mainbuf->end;
    if (!buf_write(mainbuf, offset, pkt_hdr, sizeof(*pkt_hdr)) ||
            !buf_write(mainbuf, offset + sizeof(*pkt_hdr), data, length)) {
        T2_PERR(plugin_name, "failed to append packet to main buffer");
        terminate();
    }
    mainbuf->end += sizeof(*pkt_hdr) + length;

    return offset;
}

/**
 * Extract the packets present in the to_extract buffer.
 * This function is run in a separate thread to allow other CPU intensive plugins to not
 * be blocked by this plugin disk IO.
 */
static void *extract_pkts() {
    // open output PCAP
    pcap_dumper_t *output = pcap_dump_open(captureDescriptor, output_filename);
    if (!output) {
        T2_PERR(plugin_name, "failed to open output PCAP %s", output_filename);
        exit(EXIT_FAILURE);
    }
#if LIVEXTR_SPLIT != 0
    uint64_t written_bytes = 24; // 24 = len(pcap_file_header) once written to file
#endif // LIVEXTR_SPLIT != 0

    // TODO: implement partial extraction to unlock other thread more frequently?
    uint8_t pkt_bytes[LIVEXTR_MAX_PKT_SIZE];
    while (atomic_load(&extract) || to_extract.first < to_extract.last) {
        pthread_mutex_lock(&mutex);
        while (to_extract.first < to_extract.last) {
            // offset in mainbuffer/file where packet is located
            const uint64_t offset = to_extract.offsets[to_extract.first % to_extract.allocated];
            ++to_extract.first;
            // check that packet was not yet overwritten in mainbuffer
            if (offset < mainbuffer.start) {
                continue;
            }

        #if LIVEXTR_SPLIT != 0
            // check if output PCAP needs to be switched
            //   1. based on # flows: special PCAP header
            //   2. based on # bytes: written_bytes
            if (offset == LIVEXTR_SWITCH_PCAP ||
                    (capType & OFILELN &&
                    (capType & WFINDEX) == 0 && written_bytes > file_frag_size)) {
                pcap_dump_close(output);
                ++filename_index;
                sprintf(filename_num_pos, "%" PRIu64, filename_index);
                // NOTE: there might be a problem if the main threads modify the captureDescriptor
                //       while this thread open the new output PCAP
                if (!(output = pcap_dump_open(captureDescriptor, output_filename))) {
                    T2_PERR(plugin_name, "failed to open output PCAP %s", output_filename);
                    exit(EXIT_FAILURE);
                }
                written_bytes = 24;
                continue;
            }
        #endif // LIVEXTR_SPLIT != 0

            // read packet header and data from mainbuffer/file
            struct pcap_pkthdr pkt_hdr;
            if (!buf_read(&mainbuffer, offset, &pkt_hdr, sizeof(pkt_hdr))) {
                T2_PERR(plugin_name, "failed to read stored PCAP packet header");
                exit(EXIT_FAILURE);
            }
            const size_t len = pkt_hdr.caplen;
            if (len > LIVEXTR_MAX_PKT_SIZE) {
                T2_PWRN(plugin_name, "packet too large to be extracted");
                continue;
            }
            if (!buf_read(&mainbuffer, offset + sizeof(pkt_hdr), &pkt_bytes, len)) {
                T2_PERR(plugin_name, "failed to read stored packet data");
                exit(EXIT_FAILURE);
            }

            pcap_dump((u_char *)output, &pkt_hdr, pkt_bytes);
        #if LIVEXTR_SPLIT != 0
            written_bytes += len + 16; // 16 = len(pcap_pkthdr) once written to file
        #endif // LIVEXTR_SPLIT != 0
            ++extracted_pkt_count;
        }

        // only sleep when all packets have been extracted, otherwise just unlock other thread
        // to_extract emptiness test needs to be done before unlocking
        if (to_extract.first == to_extract.last) {
            pthread_mutex_unlock(&mutex);
            usleep(1000); // sleep for 1 ms
        } else {
            pthread_mutex_unlock(&mutex);
        }
    }

    pcap_dump_close(output);

    return NULL;
}


// Tranalyzer functions


void t2Init() {
    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(liveXtr_flows);

    // initialize to_extract buffer
    to_extract.offsets = t2_calloc_fatal(LIVEXTR_INITIAL_PACKETS, sizeof(*to_extract.offsets));
    to_extract.allocated = LIVEXTR_INITIAL_PACKETS;

#if LIVEXTR_MEMORY == 0
    if (!(mainbuffer.file = fopen(LIVEXTR_FILE, "wb+"))) {
        T2_PFATAL(plugin_name, "failed to open round-robin file");
    }

    if (ftruncate(fileno(mainbuffer.file), LIVEXTR_BUFSIZE) != 0) {
        T2_PFATAL(plugin_name, "failed to resize round-robin file");
    }
#endif // LIVEXTR_MEMORY == 0

    // check max filename length (including LIVEXTR_SUFFIX_CNT_LEN digits for split output mode)
    const size_t blen = baseFileName_len;
    const size_t len = blen + sizeof(LIVEXTR_SUFFIX) + LIVEXTR_SUFFIX_CNT_LEN;
    if (UNLIKELY(len > sizeof(output_filename))) {
        T2_PFATAL(plugin_name, "filename too long");
    }

    // create the output pcap full path
    memcpy(output_filename, baseFileName, blen);
    memcpy(output_filename + blen, LIVEXTR_SUFFIX, sizeof(LIVEXTR_SUFFIX));

    // if necessary, append count at the end of the file name
#if LIVEXTR_SPLIT != 0
    if (capType & OFILELN) {
        filename_index = oFileNumB;
        file_frag_size = (uint64_t)oFragFsz;
        filename_num_pos = output_filename + strlen(output_filename);
        // append count
        sprintf(filename_num_pos, "%" PRIu64, filename_index);
    }
#endif // LIVEXTR_SPLIT != 0

    // start packets extraction thread
    if (pthread_create(&thread, NULL, &extract_pkts, NULL) != 0) {
        T2_PFATAL(plugin_name, "failed to start packets extraction thread");
    }
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    liveXtr_flow_t * const flow = &liveXtr_flows[flowIndex];
    memset(flow, '\0', sizeof(*flow)); // set everything to 0
    if (UNLIKELY(!(flow->offset_buf.offsets =
                    t2_calloc(LIVEXTR_INITIAL_PACKETS, sizeof(*flow->offset_buf.offsets))))) {
        T2_PERR(plugin_name, "failed to allocate memory for packet offsets");
        terminate();
    }
    flow->offset_buf.allocated = LIVEXTR_INITIAL_PACKETS;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    //liveXtr_flow_t * const flow = &liveXtr_flows[flowIndex];
}
#endif // ETH_ACTIVATE > 0

/**
 * Move packet offsets from the flow structure offset buffer to the to_extract list
 */
static void extract_previous(struct offset_rrbuffer *offbuf) {
    while (offbuf->first < offbuf->last) {
        add_offset(&to_extract, offbuf->offsets[offbuf->first % offbuf->allocated]);
        ++offbuf->first;
    }
}


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    const flow_t * const t2flow = &flows[flowIndex];
    liveXtr_flow_t * const flow = &liveXtr_flows[flowIndex];

    // "pause" extraction thread during mainbuffer and to_extract list modifications
    pthread_mutex_lock(&mutex);

    // always append new packet content to the main buffer
    const uint64_t offset = append_packet(&mainbuffer, packet->pcapHdrP, packet->raw_packet,
            packet->snapLen);

    // remove overwritten offset from flow structure and add new one
    if (!flow->extract) {
        clean_overwritten(&flow->offset_buf, mainbuffer.start);
        add_offset(&flow->offset_buf, offset);
    }

    // nothing more to do if this flow does not need to be extracted
    if (!(t2flow->status & LIVEXTR)) {
        pthread_mutex_unlock(&mutex);
        return;
    }

    if (!flow->extract) {
        // flow just got flagged for extraction, extract all previous packets in addition
        // to current one
        extract_previous(&flow->offset_buf);
        flow->extract = true;
    } else {
        // extract current packet
        add_offset(&to_extract, offset);
    }

    // "resume" extraction thread
    pthread_mutex_unlock(&mutex);
}


void t2OnFlowTerminate(unsigned long flowIndex) {
    const flow_t * const t2flow = &flows[flowIndex];
    liveXtr_flow_t * const flow = &liveXtr_flows[flowIndex];
    // extract all available packets if the LIVEXTR status got toggled after flow last packet
    if (t2flow->status & LIVEXTR && !flow->extract) {
        pthread_mutex_lock(&mutex);
        extract_previous(&flow->offset_buf);
        pthread_mutex_unlock(&mutex);
    }

#if LIVEXTR_SPLIT != 0
    ++terminated_flows;
    // check if output PCAP should be switched
    if (capType & WFINDEX && terminated_flows >= file_frag_size) {
        pthread_mutex_lock(&mutex);
        // special offset which indicates to the extraction thread to switch PCAP
        add_offset(&to_extract, LIVEXTR_SWITCH_PCAP);
        pthread_mutex_unlock(&mutex);
        terminated_flows = 0;
    }
#endif // LIVEXTR_SPLIT != 0

    // free dynamically allocated buffers
    free(flow->offset_buf.offsets);
    flow->offset_buf.offsets = NULL;
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, plugin_name, "Number of extracted packets", extracted_pkt_count, numPackets);
}


void t2Finalize() {
    // wait for extraction thread to terminate
    atomic_store(&extract, false);
    if (pthread_join(thread, NULL) != 0) {
        T2_PFATAL(plugin_name, "failed to wait for extraction thread to terminate");
    }

#if LIVEXTR_MEMORY == 0
    if (fclose(mainbuffer.file) != 0) {
        T2_PFATAL(plugin_name, "failed to close round-robin file");
    }

    if (unlink(LIVEXTR_FILE) != 0) {
        T2_PFATAL(plugin_name, "failed to delete round-robin file");
    }
#endif // LIVEXTR_MEMORY == 0

    free(liveXtr_flows);
    free(to_extract.offsets);
}

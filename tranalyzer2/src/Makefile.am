bin_PROGRAMS = tranalyzer

tranalyzer_CFLAGS = \
	-I$(top_srcdir)/../utils \
	-D_REENTRANT

if APPLE
tranalyzer_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
tranalyzer_CFLAGS += -D_GNU_SOURCE
endif

tranalyzer_LDFLAGS = $(LTLDFLAGS)

tranalyzer_SOURCES = \
	binaryValue.c                   \
	flow.c                          \
	hashTable.c                     \
	hdrDesc.c                       \
	ioBuffer.c                      \
	loadPlugins.c                   \
	main.c                          \
	outputBuffer.c                  \
	packetCapture.c                 \
	                                \
	hash/city.c                     \
	hash/fasthash.c                 \
	hash/hashlittle.c               \
	hash/murmur3.c                  \
	hash/xxhash.c                   \
	                                \
	proto/ayiya.c                   \
	proto/capwap.c                  \
	proto/ethertype.c               \
	proto/geneve.c                  \
	proto/gtp.c                     \
	proto/ieee80211.c               \
	proto/l2tp.c                    \
	proto/linktype.c                \
	proto/lwapp.c                   \
	proto/teredo.c                  \
	proto/vlan.c                    \
	proto/vxlan.c                   \
	                                \
	../../utils/fsutils.c           \
	../../utils/memdebug.c          \
	../../utils/subnetHL4.c         \
	../../utils/subnetHL6.c         \
	../../utils/t2log.c             \
	../../utils/t2utils.c           \
	                                \
	../../utils/missing/bsdstring.c

if APPLE
tranalyzer_SOURCES += ../../utils/missing/memrchr.c
endif

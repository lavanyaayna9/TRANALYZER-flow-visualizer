/*
 * fsutils.c
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

#if !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE < 500
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 // required for nftw
#endif // !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE < 500

#define _FILE_OFFSET_BITS 64 // fseeko and ftello work on file >4G on 32-bits machines

#include <errno.h>         // for errno, EEXIST, ENOENT
#include <ftw.h>           // for nftw, FTW (ptr only), FTW_DEPTH, FTW_DP
#include <limits.h>        // for OPEN_MAX
#include <stdbool.h>       // for false, bool, true
#include <stdint.h>        // for SIZE_MAX
#include <stdio.h>         // for fclose, fopen, fseeko, ftello, FILE, SEEK_SET
#include <stdlib.h>        // for free, NULL, size_t
#include <string.h>        // for strlen, strchr, strerror, memcpy, memset
#include <sys/queue.h>     // for TAILQ_REMOVE, TAILQ_INSERT_TAIL, TAILQ_ENTRY
#include <sys/resource.h>  // for rlimit, getrlimit, setrlimit, RLIMIT_NOFILE
#include <sys/stat.h>      // for stat, mkdir, S_ISDIR, mode_t
#include <unistd.h>        // for rmdir, unlink, off_t

#include "fsutils.h"       // for file_object_t, file_manager_t, FSUTILS_SPA...
#include "t2utils.h"       // for UNUSED, T2_FATAL, t2_malloc


static int init_rm_func(const char *fpath, const struct stat *sb  UNUSED,
        int typeflag, struct FTW *ftwbuf UNUSED) {
    // rmdir directories and unlink files
    switch (typeflag) {
        case FTW_DP:
            return rmdir(fpath);
        case FTW_F:
            return unlink(fpath);
        default:
            return -1;
    }
}

bool rmrf(const char *path) {
    // do not return an error if top directory does not exist
    struct stat sb;
    if (stat(path, &sb) != 0 && errno == ENOENT) {
        return true;
    }

    // recursively delete directory and its content
    return nftw(path, init_rm_func, FSUTILS_MAX_OPEN_FD, FTW_DEPTH | FTW_MOUNT | FTW_PHYS) == 0;
}

bool mkpath(const char *path, mode_t mode) {
    // allocate space for copy of path
    const size_t len = strlen(path);
    char * const copy = t2_malloc(len + 2); // 2 bytes for '/' + '\0'
    if (UNLIKELY(!copy)) {
        return false;
    }

    // copy path and make sure it ends with '/'
    if (UNLIKELY(memcpy(copy, path, len + 1) != copy)) {
        free(copy);
        return false;
    }

    if (copy[len - 1] != '/') {
        copy[len] = '/';
        copy[len + 1] = '\0';
    }

    // build path, directory by directory
    for (char *p = copy; *p; ++p) {
        if (*p == '/' && p != copy) {
            *p = 0;
            // make next directory
            if (mkdir(copy, mode) != 0) {
                if (errno != EEXIST) {
                    free(copy);
                    return false;
                }

                // something exists, test that it is a directory
                struct stat sb;
                if (stat(copy, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
                    free(copy);
                    return false;
                }
            }
            *p = '/';
        }
    }

    free(copy);
    return true;
}

// -------------  file manager related code  ----------------------- //

struct file_object_s {
    FILE *fp;
    off_t pos; // cursor position in file before it was closed
    // pointers for LRU
    TAILQ_ENTRY(file_object_s) lru;
    // pointers for list of all files in manager
    TAILQ_ENTRY(file_object_s) all;
    // path of file
    char *path;
    // open mode
    char mode[8];
};

struct file_manager_s {
    const size_t max;
    size_t opened;
    // LRU of opened files
    TAILQ_HEAD(, file_object_s) lru;
    // List of all existing files in manager
    TAILQ_HEAD(, file_object_s) all;
};

inline const char *file_object_get_path(const file_object_t *object) {
    return object ? object->path : NULL;
}

// set this process max file descriptors to maximum allowed by kernel
static inline size_t file_manager_maximize_fd() {
    // get max number of file descriptor allowed for this process
    struct rlimit rlp;
    if (UNLIKELY(getrlimit(RLIMIT_NOFILE, &rlp) != 0)) {
        T2_FATAL("Failed to get process file descriptors limit: %s.", strerror(errno));
    }

#ifdef __APPLE__
    if (rlp.rlim_max == RLIM_INFINITY) rlp.rlim_cur = OPEN_MAX;
    else
#endif // __APPLE__
    rlp.rlim_cur = rlp.rlim_max;

    if (UNLIKELY(setrlimit(RLIMIT_NOFILE, &rlp) != 0)) {
        T2_FATAL("Failed to set process file descriptors limit: %s", strerror(errno));
    }

    // check that the file descriptor is high enough for file manager
    if (UNLIKELY(rlp.rlim_cur < FSUTILS_MIN_FD_REQUIRED)) {
        T2_FATAL("Process file descriptor limit is too low, cannot create file manager.");
    }

    if (rlp.rlim_cur > FSUTILS_SPARE_FD) {
        return rlp.rlim_cur - FSUTILS_SPARE_FD;
    }

    return rlp.rlim_cur;
}

file_manager_t *file_manager_new(size_t max) {
    if (UNLIKELY(max == 0)) {
        T2_FATAL("Failed to create file manager: max is 0");
    }

    if (max == SIZE_MAX) {
        max = file_manager_maximize_fd();
    }

    file_manager_t * const manager = t2_malloc_fatal(sizeof(*manager));
    // ugly way to initialize const field
    *(size_t *)&manager->max = max;
    manager->opened = 0;
    TAILQ_INIT(&manager->lru);
    TAILQ_INIT(&manager->all);

    return manager;
}

void file_manager_destroy(file_manager_t *manager) {
    if (UNLIKELY(!manager)) {
        return;
    }

    // close all remaining files in manager
    while (!TAILQ_EMPTY(&manager->all)) {
        file_object_t * const file = TAILQ_FIRST(&manager->all);
        file_manager_close(manager, file);
    }

    // free memory
    free(manager);
}

// Returns true on success and false on error.
static bool open_file(file_manager_t *manager, file_object_t *file) {
    if (UNLIKELY(!manager || !file || file->fp)) {
        return false;
    }

    while (manager->opened >= manager->max) {
        // close and remove oldest file from LRU list
        file_object_t * const oldest = TAILQ_FIRST(&manager->lru);
        if (UNLIKELY(!oldest->fp)) {
            return false;
        }

        // save cursor position before closing file
        if (UNLIKELY((oldest->pos = ftello(oldest->fp)) == -1)) {
            return false;
        }

        if (UNLIKELY(fclose(oldest->fp) != 0)) {
            return false;
        }

        oldest->fp = NULL;
        TAILQ_REMOVE(&manager->lru, oldest, lru);
        --manager->opened;
    }

    // open new file and seek to correct position
    if (UNLIKELY(!(file->fp = fopen(file->path, file->mode)))) {
        return false;
    }

    if (file->pos) {
        if (UNLIKELY(fseeko(file->fp, file->pos, SEEK_SET) != 0)) {
            fclose(file->fp);
            return false;
        }
    }

    // add file to LRU list
    TAILQ_INSERT_TAIL(&manager->lru, file, lru);
    ++manager->opened;

    return true;
}

// change the file mode so the file does not get truncated on re-open
static void fix_mode(char *mode) {
    char * const w    = strchr(mode, 'w');
    char * const plus = strchr(mode, '+');
    if (!w) {
        return;
    } else if (plus) { // w && plus
        w[0] = 'r';
    } else { // w && !plus
        // replace the w by a r+
        const size_t len = strlen(mode);
        for (size_t i = w - mode + 1; i < len; ++i) {
            mode[i + 1] = mode[i];
        }
        mode[len + 1] = '\0';
        w[0] = 'r';
        w[1] = '+';
    }
}

file_object_t *file_manager_open(file_manager_t *manager, const char *path, const char *mode) {
    if (UNLIKELY(!manager || !path || !mode)) {
        return NULL;
    }

    const size_t mode_len = strlen(mode);
    if (UNLIKELY(mode_len > 6)) {
        return NULL;
    }

    // allocate memory for new file
    file_object_t *file = t2_malloc(sizeof(*file));
    if (UNLIKELY(!file)) {
        return NULL;
    }
    memset(file, 0, sizeof(*file));

    // copy file path and mode
    if (UNLIKELY(!(file->path = strdup(path)))) {
        free(file);
        return NULL;
    }
    memcpy(file->mode, mode, mode_len + 1);

    // open file
    if (UNLIKELY(!open_file(manager, file))) {
        free(file->path);
        free(file);
        return NULL;
    }
    fix_mode(file->mode);

    // add file to global list in manager
    TAILQ_INSERT_TAIL(&manager->all, file, all);

    return file;
}

bool file_manager_close(file_manager_t *manager, file_object_t *file) {
    if (UNLIKELY(!manager || !file || !file->path)) {
        return false;
    }

    // if FILE* is open, close it
    if (file->fp) {
        if (UNLIKELY(fclose(file->fp) != 0)) {
            return false; // should never happen
        }
        TAILQ_REMOVE(&manager->lru, file, lru);
        --manager->opened;
    }

    // remove from manager list of files
    TAILQ_REMOVE(&manager->all, file, all);

    // free memory
    free(file->path);
    file->path = NULL;
    free(file);

    return true;
}

FILE *file_manager_fp(file_manager_t *manager, file_object_t *file) {
    if (UNLIKELY(!manager || !file)) {
        return NULL;
    }

    if (file->fp) {
        // place file at the end of the LRU list (last one to be closed)
        TAILQ_REMOVE(&manager->lru, file, lru);
        TAILQ_INSERT_TAIL(&manager->lru, file, lru);
        return file->fp;
    }

    if (UNLIKELY(!open_file(manager, file))) {
        return NULL;
    }

    return file->fp;
}


inline int file_manager_fprintf(file_manager_t *manager, file_object_t *file, const char * const format, ...) {
    if (UNLIKELY(!manager || !file || !format)) {
        return -1;
    }

    FILE * const fp = file_manager_fp(manager, file);
    if (UNLIKELY(!fp)) {
        T2_ERR("Failed to get FILE handle for '%s' from t2_file_manager", file_object_get_path(file));
        return -1;
    }

    va_list args;
    va_start(args, format);

    const int printed = vfprintf(fp, format, args);

    va_end(args);

    return printed;
}


inline int file_manager_fputs(file_manager_t *manager, file_object_t *file, const char *restrict s) {
    if (UNLIKELY(!manager || !file || !s)) {
        return -1;
    }

    FILE * const fp = file_manager_fp(manager, file);
    if (UNLIKELY(!fp)) {
        T2_ERR("Failed to get FILE handle for '%s' from t2_file_manager", file_object_get_path(file));
        return -1;
    }

    return fputs(s, fp);
}


inline int file_manager_fputc(file_manager_t *manager, file_object_t *file, int c) {
    if (UNLIKELY(!manager || !file)) {
        return -1;
    }

    FILE * const fp = file_manager_fp(manager, file);
    if (UNLIKELY(!fp)) {
        T2_ERR("Failed to get FILE handle for '%s' from t2_file_manager", file_object_get_path(file));
        return -1;
    }

    return fputc(c, fp);
}


inline size_t file_manager_fwrite(file_manager_t *manager, file_object_t *file, const void *restrict ptr, size_t size, size_t nitems) {
    if (UNLIKELY(!manager || !file || !ptr)) {
        return -1;
    }

    FILE * const fp = file_manager_fp(manager, file);
    if (UNLIKELY(!fp)) {
        T2_ERR("Failed to get FILE handle for '%s' from t2_file_manager", file_object_get_path(file));
        return -1;
    }

    return fwrite(ptr, size, nitems, fp);
}


inline int file_manager_fflush(file_manager_t *manager, file_object_t *file) {
    if (UNLIKELY(!manager || !file)) {
        return -1;
    }

    FILE * const fp = file_manager_fp(manager, file);
    if (UNLIKELY(!fp)) {
        T2_ERR("Failed to get FILE handle for '%s' from t2_file_manager", file_object_get_path(file));
        return -1;
    }

    return fflush(fp);
}

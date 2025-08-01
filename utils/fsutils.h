/*
 * fsutils.h
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

#ifndef T2_FSUTILS_H_INCLUDED
#define T2_FSUTILS_H_INCLUDED

#include <errno.h>     // for errno
#include <stdbool.h>   // for bool
#include <stdio.h>     // for FILE, size_t
#include <sys/stat.h>  // for mode_t

#define FSUTILS_MIN_FD_REQUIRED 200 // Min process file descriptors limit required
#define FSUTILS_SPARE_FD        100 // Number of file descriptors to keep away from the file manager

#define FSUTILS_MAX_OPEN_FD 20

// equivalent of "rm -rf path"
bool rmrf(const char *path)
    __attribute__((__nonnull__(1)));

// equivalent of "mkdir -p path" where each created dir is chmod mode
bool mkpath(const char *path, mode_t mode)
    __attribute__((__nonnull__(1)));

#define T2_MKPATH_WITH_FLAGS(path, flags, overwrite) \
    if (overwrite) { \
        if (UNLIKELY(!rmrf(path))) { \
            T2_PFATAL(plugin_name, "Failed to remove directory '%s': %s", path, strerror(errno)); \
        } \
    } \
    if (UNLIKELY(!mkpath(path, flags))) { \
        T2_PFATAL(plugin_name, "Failed to create directory '%s': %s", path, strerror(errno)); \
    }
#define T2_MKPATH(path, overwrite) T2_MKPATH_WITH_FLAGS(path, S_IRWXU, overwrite)

// opaque declaration of struct used in file manager
typedef struct file_manager_s file_manager_t;
typedef struct file_object_s  file_object_t;

// Returns the path associated to a file object.
const char *file_object_get_path(const file_object_t *object);
    //__attribute__((__nonnull__(1)));

// Creates a new filemanager which keeps at most "max" files open in parallel. Returns NULL on error.
file_manager_t *file_manager_new(size_t max)
    __attribute__((__malloc__))
    __attribute__((__returns_nonnull__))
    __attribute__((__warn_unused_result__));

// Destroys a file manager.
void file_manager_destroy(file_manager_t *manager);
    //__attribute__((__nonnull__(1)));

// Opens a new file in the file manager. Returns NULL on error.
file_object_t *file_manager_open(file_manager_t *manager, const char *path, const char *mode);
    //__attribute__((__nonnull__(1, 2, 3)));

// Closes a file in the file manager. Returns true on success and false on error.
bool file_manager_close(file_manager_t *manager, file_object_t *file);
    //__attribute__((__nonnull__(1, 2)));

/*
 * Returns the FILE pointer associated to a file_object_t. Returns NULL on error.
 *
 * This function opens the file if needed, it must therefore be called each time before using a
 * function operating on the FILE*. The FILE* should not be stored and re-used later as the file
 * could be temporarily closed by the file manager when too many files are open.
 */
FILE *file_manager_fp(file_manager_t *manager, file_object_t *file);
    //__attribute__((__nonnull__(1, 2)));

/*
 * Get the FILE pointer associated to a file_object_t and call fprintf() on the FILE handle.
 * Returns -1 on error, otherwise the returned value of the call to fprintf().
 */
extern int file_manager_fprintf(file_manager_t *manager, file_object_t *file, const char * const format, ...)
    __attribute__((__format__(printf, 3, 4)))
    __attribute__((__sentinel__));
    //__attribute__((__nonnull__(1, 2, 3)));

/*
 * Get the FILE pointer associated to a file_object_t and call fputs() on the FILE handle.
 * Returns -1 on error, otherwise the returned value of the call to fputs().
 */
extern int file_manager_fputs(file_manager_t *manager, file_object_t *file, const char *s);
    //__attribute__((__nonnull__(1, 2, 3)));

/*
 * Get the FILE pointer associated to a file_object_t and call fputc() on the FILE handle.
 * Returns -1 on error, otherwise the returned value of the call to fputc().
 */
extern int file_manager_fputc(file_manager_t *manager, file_object_t *file, int c);
    //__attribute__((__nonnull__(1, 2)));

/*
 * Get the FILE pointer associated to a file_object_t and call fwrite() on the FILE handle.
 * Returns -1 on error, otherwise the returned value of the call to fwrite().
 */
extern size_t file_manager_fwrite(file_manager_t *manager, file_object_t *file, const void *ptr, size_t size, size_t nitems);
    //__attribute__((__nonnull__(1, 2, 3)));

/*
 * Get the FILE pointer associated to a file_object_t and call fflush() on the FILE handle.
 * Returns -1 on error, otherwise the returned value of the call to fflush().
 */
extern int file_manager_fflush(file_manager_t *manager, file_object_t *file);
    //__attribute__((__nonnull__(1, 2)));

#endif // T2_FSUTILS_H_INCLUDED

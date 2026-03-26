/* SPDX-License-Identifier: MIT */
#ifndef KBOX_ELF_H
#define KBOX_ELF_H

#include <stddef.h>
#include <stdint.h>

/* ELF interpreter (PT_INTERP) parsing.
 *
 * Pure computation on a byte buffer; no file I/O.
 * Used to detect dynamically linked binaries before execve.
 */

/* Parse the PT_INTERP segment from an ELF header buffer.
 * @buf:      at least 64 bytes of the ELF file header + program headers
 * @buf_len:  length of buf
 * @out:      buffer to write the interpreter path (NUL-terminated)
 * @out_size: size of out buffer
 *
 * Returns the length of the interpreter path on success (not including NUL),
 * 0 if no PT_INTERP segment (static binary), or -1 on malformed ELF.
 */
int kbox_parse_elf_interp(const unsigned char *buf,
                          size_t buf_len,
                          char *out,
                          size_t out_size);

/* Like kbox_parse_elf_interp, but also returns the file offset and size of the
 * PT_INTERP segment data. Needed for in-place patching of the interpreter path
 * (e.g. rewriting to /proc/self/fd/N).
 * @offset_out: filled with the file offset (p_offset) of the interp string
 * @filesz_out: filled with p_filesz of the PT_INTERP segment
 *
 * Both outputs are only written when the return value is > 0.
 */
int kbox_find_elf_interp_loc(const unsigned char *buf,
                             size_t buf_len,
                             char *out,
                             size_t out_size,
                             uint64_t *offset_out,
                             uint64_t *filesz_out);
int kbox_read_elf_header_window_fd(int fd,
                                   unsigned char **buf_out,
                                   size_t *buf_len_out);

struct kbox_elf_exec_segment {
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t vaddr;
    uint64_t mem_size;
};

#define KBOX_ELF_MAX_LOAD_SEGMENTS 16

struct kbox_elf_load_segment {
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t vaddr;
    uint64_t mem_size;
    uint64_t align;
    uint64_t map_align;
    uint64_t map_offset;
    uint64_t map_start;
    uint64_t map_size;
    uint32_t flags;
};

struct kbox_elf_load_plan {
    uint16_t machine;
    uint16_t type;
    uint64_t entry;
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint64_t phdr_vaddr;
    uint64_t phdr_size;
    uint64_t min_vaddr;
    uint64_t max_vaddr;
    uint64_t load_size;
    uint64_t interp_offset;
    uint64_t interp_size;
    uint32_t stack_flags;
    size_t segment_count;
    int has_interp;
    int pie;
    struct kbox_elf_load_segment segments[KBOX_ELF_MAX_LOAD_SEGMENTS];
};

int kbox_build_elf_load_plan(const unsigned char *buf,
                             size_t buf_len,
                             uint64_t page_size,
                             struct kbox_elf_load_plan *plan);

typedef int (*kbox_elf_exec_segment_cb)(const struct kbox_elf_exec_segment *seg,
                                        const unsigned char *segment_bytes,
                                        void *opaque);
typedef int (*kbox_elf_exec_segment_header_cb)(
    const struct kbox_elf_exec_segment *seg,
    void *opaque);

/* Return the ELF machine type (e_machine) for a 64-bit little-endian image. */
int kbox_elf_machine(const unsigned char *buf,
                     size_t buf_len,
                     uint16_t *machine_out);

/* Visit every PT_LOAD|PF_X segment with file-backed bytes (read-only).
 * The callback receives a const pointer to segment bytes, suitable for
 * analysis/scanning but not for in-place rewriting.  A mutable variant
 * will be needed when actual instruction replacement is implemented.
 * Returns the number of visited segments on success or -1 on malformed ELF.
 */
int kbox_visit_elf_exec_segments(const unsigned char *buf,
                                 size_t buf_len,
                                 kbox_elf_exec_segment_cb cb,
                                 void *opaque);

/* Visit executable PT_LOAD segment metadata. Only the ELF header and program
 * header table need to be present in @buf; the segment payload bytes are not
 * dereferenced.
 */
int kbox_visit_elf_exec_segment_headers(const unsigned char *buf,
                                        size_t buf_len,
                                        kbox_elf_exec_segment_header_cb cb,
                                        void *opaque);

#endif /* KBOX_ELF_H */

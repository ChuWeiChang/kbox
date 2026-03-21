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

#endif /* KBOX_ELF_H */

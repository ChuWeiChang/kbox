/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <string.h>

#include "kbox/elf.h"

/* Little-endian readers. Use memcpy to avoid unaligned access on architectures
 * that trap on it (ARMv7 without SCTLR.A clear, etc.).
 */
static uint16_t read_le16(const unsigned char *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap16(v);
#endif
    return v;
}

static uint32_t read_le32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    return v;
}

static uint64_t read_le64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

/* ELF magic: 0x7f 'E' 'L' 'F' */
static const unsigned char elf_magic[4] = {0x7f, 'E', 'L', 'F'};

#define EI_CLASS 4    /* File class byte index */
#define EI_DATA 5     /* Data encoding byte index */
#define ELFCLASS64 2  /* 64-bit objects */
#define ELFDATA2LSB 1 /* 2's complement, little endian */
#define PT_INTERP 3   /* Program interpreter */

/* ELF64 header field offsets */
#define E_PHOFF_OFF 32     /* e_phoff: uint64 */
#define E_PHENTSIZE_OFF 54 /* e_phentsize: uint16 */
#define E_PHNUM_OFF 56     /* e_phnum: uint16 */

/* ELF64 program header field offsets (relative to phdr start) */
#define P_TYPE_OFF 0    /* p_type: uint32 */
#define P_OFFSET_OFF 8  /* p_offset: uint64 */
#define P_FILESZ_OFF 32 /* p_filesz: uint64 */

#define MIN_ELF_HDR 64   /* Minimum ELF64 header size */
#define MIN_PHENTSIZE 56 /* Minimum phdr entry size */

int kbox_parse_elf_interp(const unsigned char *buf,
                          size_t buf_len,
                          char *out,
                          size_t out_size)
{
    return kbox_find_elf_interp_loc(buf, buf_len, out, out_size, NULL, NULL);
}

int kbox_find_elf_interp_loc(const unsigned char *buf,
                             size_t buf_len,
                             char *out,
                             size_t out_size,
                             uint64_t *offset_out,
                             uint64_t *filesz_out)
{
    if (!buf || buf_len < MIN_ELF_HDR || !out || out_size == 0)
        return -1;

    if (memcmp(buf, elf_magic, 4) != 0)
        return -1;

    if (buf[EI_CLASS] != ELFCLASS64 || buf[EI_DATA] != ELFDATA2LSB)
        return -1;

    uint64_t phoff = read_le64(buf + E_PHOFF_OFF);
    uint16_t phentsize = read_le16(buf + E_PHENTSIZE_OFF);
    uint16_t phnum = read_le16(buf + E_PHNUM_OFF);

    if (phentsize < MIN_PHENTSIZE)
        return -1;

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t off = phoff + (uint64_t) i * phentsize;
        if (off + MIN_PHENTSIZE > buf_len)
            break;

        uint32_t p_type = read_le32(buf + off + P_TYPE_OFF);
        if (p_type != PT_INTERP)
            continue;

        uint64_t p_offset = read_le64(buf + off + P_OFFSET_OFF);
        uint64_t p_filesz = read_le64(buf + off + P_FILESZ_OFF);

        if (p_offset >= buf_len)
            return -1;

        uint64_t end;
        if (__builtin_add_overflow(p_offset, p_filesz, &end) || end > buf_len)
            end = buf_len;

        const unsigned char *s = buf + p_offset;
        size_t slen = (size_t) (end - p_offset);

        if (slen > 0 && s[slen - 1] == '\0')
            slen--;

        if (slen == 0)
            return 0;

        if (slen >= out_size)
            slen = out_size - 1;
        memcpy(out, s, slen);
        out[slen] = '\0';

        if (offset_out)
            *offset_out = p_offset;
        if (filesz_out)
            *filesz_out = p_filesz;

        return (int) slen;
    }

    return 0;
}

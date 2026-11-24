#ifndef B8G_GHOST_H
#define B8G_GHOST_H

#include <stddef.h>
#include <stdint.h>

#define B8G_ABI_MAGIC_V3 0x33564742u /* 'BGV3' */
#define B8G_GHOST_MAGIC  0x54534847u /* 'GHST' */
#define B8G_GHOST_ABI_VER 1u

#if defined(_WIN32)
  #if defined(B8G_GHOST_BUILDING_DLL)
    #define B8G_GHOST_API __declspec(dllexport)
  #else
    #define B8G_GHOST_API
  #endif
#else
  #define B8G_GHOST_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct b8g_ghost_spec {
  uint32_t    abi_magic;     /* B8G_ABI_MAGIC_V3 */
  uint32_t    ghost_magic;   /* B8G_GHOST_MAGIC  */
  const char *filename;      /* e.g. "libsectium_display.dll" */
  const char *sha256_hex;    /* 64-char lowercase hex SHA-256 */
  const char *download_url;  /* Canonical immutable release URL */
} b8g_ghost_spec_t;

/* Pure C11 FIPS 180-4 SHA-256 of a file -> 65-byte hex string (including NUL). Returns 0 on success. */
int b8g_ghost_sha256_file(const char *path, char out_hex[65]);

/* Resolves <cas>/<sha256>/<filename>, installing from download_url on miss and verifying SHA-256.
 * Sets *out_was_hit = 1 on local CAS hit, 0 on freshly hydrated download. Returns 0 on success. */
int b8g_ghost_resolve(const b8g_ghost_spec_t *spec, char *out_path, size_t out_cap, int *out_was_hit);

/* Resolves + dynamically loads the real library via LoadLibraryA / dlopen. Returns 0 on success. */
int b8g_ghost_load(const b8g_ghost_spec_t *spec, void **out_handle, int *out_was_hit);

/* Resolves a symbol from a loaded ghost handle via GetProcAddress / dlsym. */
void *b8g_ghost_sym(void *handle, const char *symbol_name);

#ifdef __cplusplus
}
#endif

#endif /* B8G_GHOST_H */

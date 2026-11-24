/*
 * sections/b8g-ghost/src/b8g_ghost.c
 * Pure C11 Ghost Library Machine CAS Registry + FIPS 180-4 SHA-256 + Install-If-Missing Loader.
 * Zero external crypto dependencies. Works on Win64 and POSIX (Linux/macOS).
 */
#include "../include/b8g_ghost.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <direct.h>
  #define PATH_SEP '\\'
#else
  #include <dlfcn.h>
  #include <sys/stat.h>
  #include <sys/wait.h>
  #include <unistd.h>
  #include <spawn.h>
  extern char **environ;
  #define PATH_SEP '/'
#endif

/* ============================================================================
 * Minimal Embedded FIPS 180-4 SHA-256
 * ============================================================================ */

static const uint32_t SHA256_K[64] = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t  data[64];
  size_t   datalen;
} sha256_ctx_t;

static inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t block[64]) {
  uint32_t m[64];
  for (int i = 0; i < 16; ++i) {
    m[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
  }
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
    uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + SHA256_K[i] + m[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = buf[i];
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
  size_t i = ctx->datalen;
  ctx->data[i++] = 0x80;
  if (i > 56) {
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    i = 0;
  }
  while (i < 56) ctx->data[i++] = 0x00;
  ctx->bitlen += (uint64_t)ctx->datalen * 8u;
  for (int j = 7; j >= 0; --j) {
    ctx->data[56 + (7 - j)] = (uint8_t)((ctx->bitlen >> (j * 8)) & 0xffu);
  }
  sha256_transform(ctx, ctx->data);
  for (int j = 0; j < 8; ++j) {
    hash[j * 4 + 0] = (uint8_t)((ctx->state[j] >> 24) & 0xffu);
    hash[j * 4 + 1] = (uint8_t)((ctx->state[j] >> 16) & 0xffu);
    hash[j * 4 + 2] = (uint8_t)((ctx->state[j] >> 8) & 0xffu);
    hash[j * 4 + 3] = (uint8_t)(ctx->state[j] & 0xffu);
  }
}

int b8g_ghost_sha256_file(const char *path, char out_hex[65]) {
  FILE *fp = fopen(path, "rb");
  if (!fp) return -1;
  sha256_ctx_t ctx;
  sha256_init(&ctx);
  uint8_t buf[16384];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    sha256_update(&ctx, buf, n);
  }
  fclose(fp);
  uint8_t digest[32];
  sha256_final(&ctx, digest);
  static const char HEX[] = "0123456789abcdef";
  for (int i = 0; i < 32; ++i) {
    out_hex[i * 2 + 0] = HEX[(digest[i] >> 4) & 0x0f];
    out_hex[i * 2 + 1] = HEX[digest[i] & 0x0f];
  }
  out_hex[64] = '\0';
  return 0;
}

/* ============================================================================
 * Filesystem + Atomic Download Helpers (Zero Shell Injection)
 * ============================================================================ */

static void ensure_dir_recursive(const char *dir) {
  char tmp[1024];
  size_t len = strlen(dir);
  if (len == 0 || len >= sizeof(tmp)) return;
  memcpy(tmp, dir, len + 1);
  for (size_t i = 1; i < len; ++i) {
    if (tmp[i] == '/' || tmp[i] == '\\') {
      char saved = tmp[i];
      tmp[i] = '\0';
#if defined(_WIN32)
      if (!(i == 2 && tmp[1] == ':')) _mkdir(tmp);
#else
      mkdir(tmp, 0755);
#endif
      tmp[i] = saved;
    }
  }
#if defined(_WIN32)
  _mkdir(tmp);
#else
  mkdir(tmp, 0755);
#endif
}

static int file_exists_nonempty(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) return 0;
  fseek(fp, 0, SEEK_END);
  long sz = ftell(fp);
  fclose(fp);
  return sz > 0;
}

static int hex_eq_ci(const char *a, const char *b) {
  if (!a || !b) return 0;
  for (int i = 0; i < 64; ++i) {
    if (!a[i] || !b[i]) return 0;
    if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
  }
  return a[64] == '\0' && b[64] == '\0';
}

static int download_file_atomic(const char *url, const char *dest_tmp) {
#if defined(_WIN32)
  char cmd[2048];
  snprintf(cmd, sizeof(cmd), "curl.exe -fsSL --retry 2 -o \"%s\" \"%s\"", dest_tmp, url);
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    return -1;
  }
  WaitForSingleObject(pi.hProcess, 60000);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return code == 0 ? 0 : -1;
#else
  pid_t pid = 0;
  char *argv[] = {
    (char *)"curl", (char *)"-fsSL", (char *)"--retry", (char *)"2",
    (char *)"-o", (char *)dest_tmp, (char *)url, NULL
  };
  if (posix_spawnp(&pid, "curl", NULL, NULL, argv, environ) != 0) return -1;
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;
  return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
#endif
}

static void get_cas_root(char *out, size_t cap) {
  const char *override = getenv("B8G_CAS_DIR");
  if (override && override[0]) {
    snprintf(out, cap, "%s", override);
    return;
  }
#if defined(_WIN32)
  const char *local = getenv("LOCALAPPDATA");
  if (local && local[0]) {
    snprintf(out, cap, "%s\\AwesomeOS\\cas", local);
  } else {
    snprintf(out, cap, "C:\\AwesomeOS\\cas");
  }
#else
  const char *home = getenv("HOME");
  if (home && home[0]) {
    snprintf(out, cap, "%s/.local/share/awesome-os/cas", home);
  } else {
    snprintf(out, cap, "/tmp/awesome-os-cas");
  }
#endif
}

int b8g_ghost_resolve(const b8g_ghost_spec_t *spec, char *out_path, size_t out_cap, int *out_was_hit) {
  if (!spec || spec->abi_magic != B8G_ABI_MAGIC_V3 || spec->ghost_magic != B8G_GHOST_MAGIC) return -1;
  if (!spec->filename || !spec->sha256_hex || !spec->download_url) return -2;

  char cas_root[512];
  get_cas_root(cas_root, sizeof(cas_root));

  char entry_dir[768];
  snprintf(entry_dir, sizeof(entry_dir), "%s%c%s", cas_root, PATH_SEP, spec->sha256_hex);

  char target_path[1024];
  snprintf(target_path, sizeof(target_path), "%s%c%s", entry_dir, PATH_SEP, spec->filename);

  /* Fast path: local machine CAS hit */
  if (file_exists_nonempty(target_path)) {
    char actual[65];
    if (b8g_ghost_sha256_file(target_path, actual) == 0 && hex_eq_ci(actual, spec->sha256_hex)) {
      if (out_was_hit) *out_was_hit = 1;
      snprintf(out_path, out_cap, "%s", target_path);
      return 0;
    }
  }

  /* Cold path: install-if-missing into machine CAS with strict SHA-256 verification */
  ensure_dir_recursive(entry_dir);
  char tmp_path[1088];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", target_path);

  if (download_file_atomic(spec->download_url, tmp_path) != 0) {
    remove(tmp_path);
    return -3;
  }

  char actual[65];
  if (b8g_ghost_sha256_file(tmp_path, actual) != 0 || !hex_eq_ci(actual, spec->sha256_hex)) {
    remove(tmp_path);
    return -4; /* SHA-256 mismatch — tampered or corrupt download rejected */
  }

  remove(target_path);
  if (rename(tmp_path, target_path) != 0) {
    remove(tmp_path);
    return -5;
  }

  if (out_was_hit) *out_was_hit = 0;
  snprintf(out_path, out_cap, "%s", target_path);
  return 0;
}

int b8g_ghost_load(const b8g_ghost_spec_t *spec, void **out_handle, int *out_was_hit) {
  if (!out_handle) return -1;
  char resolved[1024];
  int rc = b8g_ghost_resolve(spec, resolved, sizeof(resolved), out_was_hit);
  if (rc != 0) return rc;
#if defined(_WIN32)
  HMODULE h = LoadLibraryA(resolved);
  if (!h) return -6;
  *out_handle = (void *)h;
#else
  void *h = dlopen(resolved, RTLD_NOW | RTLD_LOCAL);
  if (!h) return -6;
  *out_handle = h;
#endif
  return 0;
}

void *b8g_ghost_sym(void *handle, const char *symbol_name) {
  if (!handle || !symbol_name) return NULL;
#if defined(_WIN32)
  return (void *)GetProcAddress((HMODULE)handle, symbol_name);
#else
  return dlsym(handle, symbol_name);
#endif
}

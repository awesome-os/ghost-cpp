#include "b8g_ghost.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  b8g_ghost_spec_t spec;
  spec.abi_magic   = B8G_ABI_MAGIC_V3;
  spec.ghost_magic = B8G_GHOST_MAGIC;
#if defined(_WIN32)
  spec.filename     = "libbrotli-win64.dll";
  spec.sha256_hex   = "9d6578ccaa0d97b540652a1f7b621bcbfcd5337b56e8a6c2cb1eba856c903238";
  spec.download_url = "https://github.com/awesome-os/b8g-ghost/releases/download/cas-v1/9d6578ccaa0d97b540652a1f7b621bcbfcd5337b56e8a6c2cb1eba856c903238";
#else
  spec.filename     = "libbrotli-linux-x64.so";
  spec.sha256_hex   = "f9b6f07e449334d3927848394cf6f9b9d69c0d19e51d2e89d01f9867262135a4";
  spec.download_url = "https://github.com/awesome-os/b8g-ghost/releases/download/cas-v1/f9b6f07e449334d3927848394cf6f9b9d69c0d19e51d2e89d01f9867262135a4";
#endif

  void *handle = NULL;
  int hit = 0;
  if (b8g_ghost_load(&spec, &handle, &hit) != 0) {
    fprintf(stderr, "[ghost-cpp] Failed to hydrate/load %s\n", spec.filename);
    return 1;
  }
  typedef uint32_t (*ver_fn)(void);
  ver_fn fn = (ver_fn)b8g_ghost_sym(handle, "BrotliDecoderVersion");
  if (!fn) {
    fprintf(stderr, "[ghost-cpp] Missing BrotliDecoderVersion symbol\n");
    return 2;
  }
  uint32_t ver = fn();
  printf("[ghost-cpp] [%s] Native BrotliDecoderVersion() = 0x%x (zero vcpkg/Conan/CMake!)\n",
         hit ? "CAS-HIT " : "HYDRATED", ver);
  return ver > 0x01000000u ? 0 : 3;
}

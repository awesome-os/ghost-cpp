# `awesome-os/ghost-cpp` — Zero-`vcpkg`, Zero-`Conan`, Zero-CMake C/C++ Package Hydration

> **Eliminates:** `vcpkg install`, `conan install`, 40-minute local CMake/Make builds, incompatible glibc/MSVC CRT mismatches.  
> **Canonical Store:** [`awesome-os/b8g-ghost @ cas-v1`](https://github.com/awesome-os/b8g-ghost/releases/tag/cas-v1) (`manifests/index.json`)

## 1-Command Build & Live Execution (Pure C11 — Zero CMake, Zero `vcpkg`, Zero `Conan`)

```bash
cc -O2 -Iinclude src/b8g_ghost.c examples/brotli_demo.c -ldl -o brotli_demo && ./brotli_demo
```

On first run, `brotli_demo` hydrates `libbrotli` from **`awesome-os/b8g-ghost @ cas-v1`** into your shared Machine CAS, verifies FIPS 180-4 SHA-256, loads it via `dlopen`/`LoadLibrary`, and executes native `BrotliDecoderVersion()`. Every subsequent run hits local CAS in `0 ms`!

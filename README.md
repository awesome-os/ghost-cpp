# `awesome-os/ghost-cpp` — Zero-`vcpkg`, Zero-`Conan`, Zero-CMake C/C++ Package Hydration

> **Eliminates:** `vcpkg install`, `conan install`, 40-minute local CMake/Make builds, incompatible glibc/MSVC CRT mismatches.  
> **Canonical Store:** [`awesome-os/b8g-ghost @ cas-v1`](https://github.com/awesome-os/b8g-ghost/releases/tag/cas-v1) (`manifests/index.json`)

## Quick Install & Usage

### Install via `pnpm` (or release tarball)

```powershell
pnpm add github:awesome-os/ghost-cpp
```

Or download the latest SHA-256 verified archive from [`Releases`](https://github.com/awesome-os/ghost-cpp/releases/latest).

### Usage & Verification

```bash
# Compile and run the pure C11 Ghost CAS demo (zero CMake / vcpkg / Conan)
cc -O2 -Iinclude src/b8g_ghost.c examples/brotli_demo.c -ldl -o brotli_demo && ./brotli_demo
```

## 1-Command Build & Live Execution (Pure C11 — Zero CMake, Zero `vcpkg`, Zero `Conan`)

```bash
cc -O2 -Iinclude src/b8g_ghost.c examples/brotli_demo.c -ldl -o brotli_demo && ./brotli_demo
```

On first run, `brotli_demo` hydrates `libbrotli` from **`awesome-os/b8g-ghost @ cas-v1`** into your shared Machine CAS, verifies FIPS 180-4 SHA-256, loads it via `dlopen`/`LoadLibrary`, and executes native `BrotliDecoderVersion()`. Every subsequent run hits local CAS in `0 ms`!

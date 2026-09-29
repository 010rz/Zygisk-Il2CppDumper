#include "hack.h"
#include "log.h"
#include "game.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <vector>

#define GL_UNSIGNED_BYTE 0x1401
#define GL_RGB 0x1907
#define GL_RGBA 0x1908
#define GL_LUMINANCE 0x1909
#define GL_LUMINANCE_ALPHA 0x190A
#define GL_ALPHA 0x1906
#define GL_BGRA_EXT 0x80E1
#define GL_RGBA8 0x8058
#define GL_RGB8 0x8051

using eglGetProcAddress_t = void *(*)(const char *);
using glTexImage2D_t = void (*)(unsigned, int, int, int, int, int, unsigned, unsigned, const void *);
using glCompressedTexImage2D_t = void (*)(unsigned, int, unsigned, int, int, int, int, const void *);
using glTexSubImage2D_t = void (*)(unsigned, int, int, int, int, int, unsigned, unsigned, const void *);

static eglGetProcAddress_t orig_eglGetProcAddress;
static glTexImage2D_t orig_glTexImage2D;
static glCompressedTexImage2D_t orig_glCompressedTexImage2D;
static glTexSubImage2D_t orig_glTexSubImage2D;

static std::atomic_bool g_started{false};
static std::atomic_int g_index{0};
static std::mutex g_mu;
static std::unordered_set<uint64_t> g_seen;
static std::unordered_set<void *> g_hooked;
static char g_dir[512];
static const int kMaxFiles = 800;
static const int kMinDim = 32;

static uint64_t fnv(const void *p, size_t n, uint64_t h = 1469598103934665603ull) {
    auto *b = static_cast<const uint8_t *>(p);
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

static bool ensure_dir(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        return true;
    }
    LOGE("mkdir %s failed: %s", path, strerror(errno));
    return false;
}

static bool write_all(int fd, const void *buf, size_t n) {
    auto *p = static_cast<const uint8_t *>(buf);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        off += static_cast<size_t>(w);
    }
    return true;
}

#if defined(__aarch64__)
static void emit_abs_jump(uint8_t *dst, void *to) {
    uint32_t ldr = 0x58000050u | (2u << 5);
    uint32_t br = 0xD61F0200u;
    memcpy(dst, &ldr, 4);
    memcpy(dst + 4, &br, 4);
    memcpy(dst + 8, &to, 8);
}

static int hook_arm64(void *target, void *replace, void **orig_out) {
    if (!target || !replace) {
        return -1;
    }
    if (g_hooked.count(target)) {
        return 0;
    }
    uint8_t stolen[16];
    memcpy(stolen, target, 16);
    void *exec = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec == MAP_FAILED) {
        return -2;
    }
    auto *tr = static_cast<uint8_t *>(exec);
    memcpy(tr, stolen, 16);
    emit_abs_jump(tr + 16, reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(target) + 16));
    __builtin___clear_cache(reinterpret_cast<char *>(exec), reinterpret_cast<char *>(exec) + 32);
    if (orig_out && *orig_out == nullptr) {
        *orig_out = exec;
    }

    uintptr_t page = reinterpret_cast<uintptr_t>(target) & ~0xFFFull;
    if (mprotect(reinterpret_cast<void *>(page), 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed %s", strerror(errno));
        return -3;
    }
    emit_abs_jump(static_cast<uint8_t *>(target), replace);
    __builtin___clear_cache(static_cast<char *>(target), static_cast<char *>(target) + 16);
    g_hooked.insert(target);
    return 0;
}
#else
static int hook_arm64(void *, void *, void **) { return -100; }
#endif

#pragma pack(push, 1)
struct TgaHeader {
    uint8_t id_len;
    uint8_t color_map;
    uint8_t type;
    uint16_t cm_first;
    uint16_t cm_len;
    uint8_t cm_size;
    uint16_t x;
    uint16_t y;
    uint16_t w;
    uint16_t h;
    uint8_t bpp;
    uint8_t desc;
};
#pragma pack(pop)

static bool write_tga(const char *path, int w, int h, int src_bpp, const uint8_t *src,
                      unsigned gl_format) {
    if (w <= 0 || h <= 0 || !src || src_bpp <= 0) {
        return false;
    }
    int dst_bpp = (src_bpp == 3) ? 24 : 32;
    size_t row_src = static_cast<size_t>(w) * static_cast<size_t>(src_bpp);
    size_t row_dst = static_cast<size_t>(w) * static_cast<size_t>(dst_bpp / 8);
    std::vector<uint8_t> body(row_dst * static_cast<size_t>(h));
    for (int y = 0; y < h; y++) {
        const uint8_t *s = src + static_cast<size_t>(y) * row_src;
        uint8_t *d = body.data() + static_cast<size_t>(y) * row_dst;
        for (int x = 0; x < w; x++) {
            uint8_t r = 0, g = 0, b = 0, a = 255;
            if (src_bpp == 1) {
                r = g = b = s[x];
            } else if (src_bpp == 2) {
                r = g = b = s[x * 2];
                a = s[x * 2 + 1];
            } else if (src_bpp == 3) {
                r = s[x * 3];
                g = s[x * 3 + 1];
                b = s[x * 3 + 2];
            } else if (gl_format == GL_BGRA_EXT) {
                b = s[x * 4];
                g = s[x * 4 + 1];
                r = s[x * 4 + 2];
                a = s[x * 4 + 3];
            } else {
                r = s[x * 4];
                g = s[x * 4 + 1];
                b = s[x * 4 + 2];
                a = s[x * 4 + 3];
            }
            if (dst_bpp == 24) {
                d[x * 3 + 0] = b;
                d[x * 3 + 1] = g;
                d[x * 3 + 2] = r;
            } else {
                d[x * 4 + 0] = b;
                d[x * 4 + 1] = g;
                d[x * 4 + 2] = r;
                d[x * 4 + 3] = a;
            }
        }
    }
    TgaHeader hdr{};
    hdr.type = 2;
    hdr.w = static_cast<uint16_t>(w);
    hdr.h = static_cast<uint16_t>(h);
    hdr.bpp = static_cast<uint8_t>(dst_bpp);
    hdr.desc = (dst_bpp == 32) ? 0x28 : 0x20;
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        return false;
    }
    bool ok = write_all(fd, &hdr, sizeof(hdr)) && write_all(fd, body.data(), body.size());
    close(fd);
    return ok;
}

static int src_bpp_of(unsigned format, unsigned type) {
    if (type != GL_UNSIGNED_BYTE) {
        return 0;
    }
    switch (format) {
        case GL_RGBA:
        case GL_BGRA_EXT:
        case GL_RGBA8:
            return 4;
        case GL_RGB:
        case GL_RGB8:
            return 3;
        case GL_LUMINANCE_ALPHA:
            return 2;
        case GL_LUMINANCE:
        case GL_ALPHA:
            return 1;
        default:
            return 0;
    }
}

static void dump_pixels(const char *kind, int level, int width, int height, unsigned format,
                        unsigned type, unsigned internalformat, int imageSize, const void *pixels) {
    if (!pixels || level != 0) {
        return;
    }
    if (width < kMinDim || height < kMinDim || width > 8192 || height > 8192) {
        return;
    }
    int bpp = src_bpp_of(format, type);
    size_t nbytes = 0;
    if (imageSize > 0) {
        nbytes = static_cast<size_t>(imageSize);
    } else if (bpp > 0) {
        nbytes = static_cast<size_t>(width) * static_cast<size_t>(height) * static_cast<size_t>(bpp);
    } else {
        LOGI("skip %s %dx%d fmt=0x%x type=0x%x ifmt=0x%x", kind, width, height, format, type,
             internalformat);
        return;
    }
    uint64_t h = fnv(&width, sizeof(width));
    h = fnv(&height, sizeof(height), h);
    h = fnv(&format, sizeof(format), h);
    h = fnv(&internalformat, sizeof(internalformat), h);
    h = fnv(&type, sizeof(type), h);
    size_t sample = nbytes < 4096 ? nbytes : 4096;
    h = fnv(pixels, sample, h);
    if (nbytes > 4096) {
        h = fnv(static_cast<const uint8_t *>(pixels) + nbytes - sample, sample, h);
    }
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_seen.count(h) || g_index.load() >= kMaxFiles) {
        return;
    }
    g_seen.insert(h);
    int idx = g_index.fetch_add(1);
    char path[768];
    if (imageSize > 0 && bpp == 0) {
        snprintf(path, sizeof(path), "%s/%04d_%dx%d_ifmt%x.bin", g_dir, idx, width, height,
                 internalformat);
        int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (fd >= 0) {
            write_all(fd, pixels, nbytes);
            close(fd);
            LOGI("dump compressed %s", path);
        }
        return;
    }
    snprintf(path, sizeof(path), "%s/%04d_%dx%d_fmt%x.tga", g_dir, idx, width, height, format);
    if (write_tga(path, width, height, bpp, static_cast<const uint8_t *>(pixels), format)) {
        LOGI("dump %s", path);
    } else {
        LOGE("write failed %s (%s)", path, strerror(errno));
    }
}

static void my_glTexImage2D(unsigned target, int level, int internalformat, int width, int height,
                            int border, unsigned format, unsigned type, const void *pixels) {
    dump_pixels("tex", level, width, height, format, type, static_cast<unsigned>(internalformat), 0,
                pixels);
    orig_glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
}

static void my_glCompressedTexImage2D(unsigned target, int level, unsigned internalformat, int width,
                                      int height, int border, int imageSize, const void *data) {
    dump_pixels("ctex", level, width, height, 0, 0, internalformat, imageSize, data);
    orig_glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize,
                                data);
}

static void my_glTexSubImage2D(unsigned target, int level, int xoffset, int yoffset, int width,
                               int height, unsigned format, unsigned type, const void *pixels) {
    if (xoffset == 0 && yoffset == 0) {
        dump_pixels("sub", level, width, height, format, type, format, 0, pixels);
    }
    orig_glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels);
}

static void *my_eglGetProcAddress(const char *name) {
    void *p = orig_eglGetProcAddress ? orig_eglGetProcAddress(name) : nullptr;
    if (!name) {
        return p;
    }
    if (strcmp(name, "glTexImage2D") == 0) {
        if (p && orig_glTexImage2D == nullptr) {
            orig_glTexImage2D = reinterpret_cast<glTexImage2D_t>(p);
        }
        return reinterpret_cast<void *>(my_glTexImage2D);
    }
    if (strcmp(name, "glCompressedTexImage2D") == 0) {
        if (p && orig_glCompressedTexImage2D == nullptr) {
            orig_glCompressedTexImage2D = reinterpret_cast<glCompressedTexImage2D_t>(p);
        }
        return reinterpret_cast<void *>(my_glCompressedTexImage2D);
    }
    if (strcmp(name, "glTexSubImage2D") == 0) {
        if (p && orig_glTexSubImage2D == nullptr) {
            orig_glTexSubImage2D = reinterpret_cast<glTexSubImage2D_t>(p);
        }
        return reinterpret_cast<void *>(my_glTexSubImage2D);
    }
    return p;
}

static void *dlsym_lib(const char *lib, const char *sym) {
    void *h = dlopen(lib, RTLD_NOW);
    if (!h) {
        return nullptr;
    }
    return dlsym(h, sym);
}

static void install_hooks() {
    void *tex = dlsym_lib("libGLESv2.so", "glTexImage2D");
    if (tex) {
        void *orig = nullptr;
        if (hook_arm64(tex, reinterpret_cast<void *>(my_glTexImage2D), &orig) == 0 && orig) {
            orig_glTexImage2D = reinterpret_cast<glTexImage2D_t>(orig);
            LOGI("glTexImage2D hooked %p orig=%p", tex, orig);
        }
    }
    void *ctex = dlsym_lib("libGLESv2.so", "glCompressedTexImage2D");
    if (ctex) {
        void *orig = nullptr;
        if (hook_arm64(ctex, reinterpret_cast<void *>(my_glCompressedTexImage2D), &orig) == 0 && orig) {
            orig_glCompressedTexImage2D = reinterpret_cast<glCompressedTexImage2D_t>(orig);
            LOGI("glCompressedTexImage2D hooked");
        }
    }
    void *sub = dlsym_lib("libGLESv2.so", "glTexSubImage2D");
    if (sub) {
        void *orig = nullptr;
        if (hook_arm64(sub, reinterpret_cast<void *>(my_glTexSubImage2D), &orig) == 0 && orig) {
            orig_glTexSubImage2D = reinterpret_cast<glTexSubImage2D_t>(orig);
            LOGI("glTexSubImage2D hooked");
        }
    }
    void *egl = dlsym_lib("libEGL.so", "eglGetProcAddress");
    if (egl) {
        void *orig = nullptr;
        if (hook_arm64(egl, reinterpret_cast<void *>(my_eglGetProcAddress), &orig) == 0 && orig) {
            orig_eglGetProcAddress = reinterpret_cast<eglGetProcAddress_t>(orig);
            LOGI("eglGetProcAddress hooked orig=%p", orig);
        } else {
            LOGE("eglGetProcAddress hook failed");
        }
    } else {
        LOGW("eglGetProcAddress not found");
    }
}

struct DumpArg {
    char dir[512];
};

static void *texdump_thread(void *p) {
    auto *arg = static_cast<DumpArg *>(p);
    snprintf(g_dir, sizeof(g_dir), "%s/files/texdump", arg->dir);
    char files[600];
    snprintf(files, sizeof(files), "%s/files", arg->dir);
    ensure_dir(files);
    if (!ensure_dir(g_dir)) {
        snprintf(g_dir, sizeof(g_dir), "/sdcard/Download/texdump");
        ensure_dir(g_dir);
    }
    LOGI("texdump dir %s", g_dir);
    bool hooked = false;
    for (int i = 0; i < 80; i++) {
        void *egl = dlopen("libEGL.so", RTLD_NOW);
        if (egl && dlsym(egl, "eglGetProcAddress")) {
            install_hooks();
            hooked = true;
            break;
        }
        usleep(100 * 1000);
    }
    free(arg);
    if (!hooked) {
        LOGE("give up waiting GLES");
        return nullptr;
    }
    LOGI("texdump hooks installed");
    return nullptr;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    (void)data;
    (void)length;
    if (g_started.exchange(true)) {
        return;
    }
    LOGI("texdump start dir=%s", game_data_dir ? game_data_dir : "(null)");
    auto *arg = static_cast<DumpArg *>(calloc(1, sizeof(DumpArg)));
    const char *d = game_data_dir ? game_data_dir : "/data/data/" GamePackageName;
    strncpy(arg->dir, d, sizeof(arg->dir) - 1);
    pthread_t th;
    pthread_create(&th, nullptr, texdump_thread, arg);
    pthread_detach(th);
}

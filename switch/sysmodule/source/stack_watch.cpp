// See stack_watch.hpp.
#include <stratosphere.hpp>

#include <cstring>

#include "log.hpp"
#include "stack_watch.hpp"

namespace ams::stack_watch {

    namespace {

        constexpr u8 Pattern = 0xA5;
        constexpr size_t MaxStacks = 12;

        struct Stack {
            const char *name;
            const u8 *base;  // lowest address (main thread)
            size_t size;
            os::ThreadType *thread;  // threads we created: read via their mapping
        };

        constinit Stack g_stacks[MaxStacks] = {};
        constinit size_t g_count = 0;

        void Track(const Stack &s) {
            if (g_count < MaxStacks) g_stacks[g_count++] = s;
        }

        // Where the stack is readable now, and its size.
        const u8 *Mapped(const Stack &s, size_t *size) {
            if (!s.thread) {
                *size = s.size;
                return s.base;
            }
            const ::Thread *t = s.thread->thread_impl;
            *size = t->stack_sz;
            return static_cast<const u8 *>(t->stack_mirror);
        }

        size_t Used(const Stack &s) {
            size_t size = 0;
            const u8 *base = Mapped(s, std::addressof(size));
            if (!base) return 0;
            size_t untouched = 0;
            while (untouched < size && base[untouched] == Pattern) untouched++;
            return size - untouched;
        }

    }

    void Paint(void *stack, size_t size) {
        std::memset(stack, Pattern, size);
    }

    void Add(const char *name, os::ThreadType *thread) {
        Track(Stack{name, nullptr, 0, thread});
    }

    NOINLINE void AddCurrent(const char *name) {
        // Ask the kernel which mapping holds our stack pointer rather than
        // trusting thread bookkeeping (wrong bounds here mean a data abort).
        const uintptr_t sp = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
        ::MemoryInfo info = {};
        u32 page_info = 0;
        if (R_FAILED(svcQueryMemory(std::addressof(info), std::addressof(page_info), sp))) return;
        if ((info.perm & Perm_Rw) != Perm_Rw || info.addr > sp || sp - info.addr > info.size) return;
        // Leave a margin below our own frame alone.
        const uintptr_t base = info.addr, top = info.addr + info.size, end = sp - 1024;
        if (end <= base) return;
        volatile u8 *p = reinterpret_cast<volatile u8 *>(base);
        for (uintptr_t a = base; a < end; a++) *p++ = Pattern;
        Track(Stack{name, reinterpret_cast<const u8 *>(base), top - base, nullptr});
    }

    void Log() {
        char line[256];
        size_t n = 0;
        for (size_t i = 0; i < g_count; i++) {
            bool seen = false;
            for (size_t j = 0; j < i; j++) seen |= std::strcmp(g_stacks[j].name, g_stacks[i].name) == 0;
            if (seen) continue;
            size_t used = 0, count = 0;
            for (size_t j = i; j < g_count; j++) {
                if (std::strcmp(g_stacks[j].name, g_stacks[i].name) != 0) continue;
                used = std::max(used, Used(g_stacks[j]));
                count++;
            }
            size_t size = 0;
            Mapped(g_stacks[i], std::addressof(size));
            n += util::SNPrintf(line + n, sizeof line - n, "%s%s %zu/%zu KB%s", n ? ", " : "", g_stacks[i].name, (used + 1023) / 1024,
                                size / 1024, count > 1 ? " (max)" : "");
            if (n >= sizeof line) break;
        }
        ams::Log("stacks used: %s", line);
    }

}

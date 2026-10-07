// Stack high-water marks, to size thread stacks from measurements: a stack
// is filled with a pattern before use, and the deepest byte that no longer
// holds it shows how much was ever used.
#pragma once
#include <stratosphere.hpp>

namespace ams::stack_watch {

    // Fills a stack buffer; call before os::CreateThread, which (through
    // libnx) remaps the buffer into the stack region and locks the original.
    void Paint(void *stack, size_t size);
    // Tracks a created thread's stack (read through its mapping).
    void Add(const char *name, os::ThreadType *thread);
    // Fills the unused part of the calling thread's stack and tracks it.
    void AddCurrent(const char *name);
    // Logs used/size per name (the maximum where several share a name).
    void Log();

}

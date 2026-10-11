// The sysmodule's heap size, written by tools/footprint.sh (make sysmodule):
// it fills the sysmodule's memory up to exactly 2.5 MB (2560 KB) with the
// code as built. Commit it with the code change that moved it.
#define TSNX_HEAP_SIZE 0xCC000

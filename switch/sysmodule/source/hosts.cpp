// See hosts.hpp.
#include <stratosphere.hpp>

#include <cstring>
#include <memory>

#include "hosts.hpp"
#include "log.hpp"

namespace ams::hosts {

    namespace {

        constexpr const char BeginMarker[] = "# >>> tailscale-nx: tailnet names, rewritten automatically; edit outside this block >>>\n";
        constexpr const char EndMarker[] = "# <<< tailscale-nx <<<\n";

        // Atmosphère aborts (taking the console down) on a hosts file of
        // 32 KB or more, or a name of 512+ bytes; stay well clear of both.
        constexpr size_t MaxFile = 24_KB;
        constexpr size_t MaxBlock = 8_KB;
        constexpr size_t MaxName = 253;

        // The block last written (FNV-1a), to skip rewriting an unchanged one.
        constinit u64 g_last_block_hash = 0;

        u64 Hash(const char *p, size_t n) {
            u64 h = 0xcbf29ce484222325ull;
            for (size_t i = 0; i < n; i++) h = (h ^ static_cast<u8>(p[i])) * 0x100000001b3ull;
            return h;
        }

        // The file Atmosphère's dns_mitm reads (its SelectHostsFile), among
        // those that exist; false if none does (then we leave it alone:
        // creating a higher-priority file would hide the user's).
        bool SelectPath(char *out, size_t cap) {
            auto exists = [](const char *p) {
                fs::DirectoryEntryType t;
                return R_SUCCEEDED(fs::GetEntryType(std::addressof(t), p)) && t == fs::DirectoryEntryType_File;
            };
            if (emummc::IsActive()) {
                util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/emummc_%04x.txt", emummc::GetActiveId());
                if (exists(out)) return true;
                util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/emummc.txt");
                if (exists(out)) return true;
            } else {
                util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/sysmmc.txt");
                if (exists(out)) return true;
            }
            util::SNPrintf(out, cap, "sdmc:/atmosphere/hosts/default.txt");
            return exists(out);
        }

        bool ValidName(const char *s, size_t n) {
            if (n == 0 || n > MaxName || s[0] == '.' || s[0] == '-') return false;
            for (size_t i = 0; i < n; i++) {
                const char c = s[i];
                const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
                if (!ok) return false;
            }
            // Atmosphère checks later entries first, so ours (the file's
            // last block) win: never add names that could shadow anything
            // else. Exact names only match themselves, but a peer called
            // "localhost" would still take that name over.
            if (n == 9 && std::strncmp(s, "localhost", 9) == 0) return false;
            // Nor anything that could look like a Nintendo host.
            for (size_t i = 0; i + 8 <= n; i++) {
                bool match = true;
                for (size_t j = 0; j < 8 && match; j++) match = (s[i + j] | 0x20) == "nintendo"[j];
                if (match) return false;
            }
            return true;
        }

        // Builds the managed block from "ip name\n" lines. Returns its length
        // (0: no valid entries).
        size_t BuildBlock(const char *lines, char *out, size_t cap, int *count) {
            size_t n = util::SNPrintf(out, cap, "%s", BeginMarker);
            *count = 0;
            for (const char *line = lines; *line;) {
                const char *eol = std::strchr(line, '\n');
                const size_t len = eol ? static_cast<size_t>(eol - line) : std::strlen(line);
                const char *sp = static_cast<const char *>(std::memchr(line, ' ', len));
                if (sp) {
                    const size_t ip_len = static_cast<size_t>(sp - line), name_len = len - ip_len - 1;
                    const char *name = sp + 1;
                    const char *dot = static_cast<const char *>(std::memchr(name, '.', name_len));
                    const size_t short_len = dot ? static_cast<size_t>(dot - name) : 0;
                    if (ip_len <= 15 && ValidName(name, name_len)) {
                        char entry[600];
                        int m = util::SNPrintf(entry, sizeof entry, "%.*s %.*s", static_cast<int>(ip_len), line, static_cast<int>(name_len), name);
                        if (short_len > 0 && ValidName(name, short_len)) {
                            m += util::SNPrintf(entry + m, sizeof entry - m, " %.*s", static_cast<int>(short_len), name);
                        }
                        m += util::SNPrintf(entry + m, sizeof entry - m, "\n");
                        if (n + m + sizeof EndMarker >= cap) break;  // block full: keep what fits
                        std::memcpy(out + n, entry, m);
                        n += m;
                        ++*count;
                    }
                }
                line += eol ? len + 1 : len;
            }
            n += util::SNPrintf(out + n, cap - n, "%s", EndMarker);
            return *count > 0 ? n : 0;
        }

        // Removes a previous block (both markers present) from text[0..len).
        size_t StripBlock(char *text, size_t len) {
            char *begin = std::strstr(text, BeginMarker);
            if (!begin) return len;
            char *end = std::strstr(begin, EndMarker);
            if (!end) return len;  // half a block: leave the file as it is
            end += sizeof EndMarker - 1;
            std::memmove(begin, end, text + len - end + 1);
            return len - static_cast<size_t>(end - begin);
        }

        void ReloadAtmosphereHosts() {
            ::Service srv;
            if (R_FAILED(smGetService(std::addressof(srv), "sfdnsres"))) return;
            // 65000: AtmosphereReloadHostsFile (Atmosphère dns_mitm only).
            const ::Result rc = serviceDispatch(std::addressof(srv), 65000);
            serviceClose(std::addressof(srv));
            if (R_FAILED(rc)) Log("hosts: Atmosphere did not reload (dns_mitm disabled?): 0x%x", rc);
        }

    }

    void Update(TsnxEngine *engine) {
        // Runs rarely: working buffers come from the heap, not static memory.
        auto lines = std::make_unique<char[]>(MaxBlock);
        auto block = std::make_unique<char[]>(MaxBlock);
        tsnx_engine_hosts(engine, lines.get(), MaxBlock);
        int count = 0;
        const size_t block_len = BuildBlock(lines.get(), block.get(), MaxBlock, std::addressof(count));
        const u64 hash = Hash(block.get(), block_len);
        if (hash == g_last_block_hash) return;
        lines.reset();

        char path[0x60];
        if (!SelectPath(path, sizeof path)) {
            Log("hosts: no Atmosphere hosts file to add tailnet names to");
            return;
        }

        // Read the whole file; anything unexpected means we don't write.
        auto text = std::make_unique<char[]>(MaxFile + MaxBlock + 2);
        fs::FileHandle f;
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) return;
        s64 size = 0;
        size_t got = 0;
        const bool read_ok = R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size >= 0 && static_cast<size_t>(size) <= MaxFile &&
                             R_SUCCEEDED(fs::ReadFile(std::addressof(got), f, 0, text.get(), static_cast<size_t>(size))) &&
                             got == static_cast<size_t>(size);
        fs::CloseFile(f);
        if (!read_ok) {
            Log("hosts: %s is unreadable or over %zu KB; not touching it", path, MaxFile / 1024);
            return;
        }
        text[got] = 0;
        if (std::strlen(text.get()) != got) return;  // embedded NUL: not a text file we understand

        size_t len = StripBlock(text.get(), got);
        if (len > 0 && text[len - 1] != '\n') text[len++] = '\n';
        std::memcpy(text.get() + len, block.get(), block_len);
        len += block_len;
        if (len > MaxFile) {
            Log("hosts: %s would grow past %zu KB; not adding tailnet names", path, MaxFile / 1024);
            return;
        }

        // In place (write, then trim), so the file never goes missing: a
        // reload that can't open it aborts Atmosphère's dns_mitm.
        if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) return;
        const bool ok = R_SUCCEEDED(fs::WriteFile(f, 0, text.get(), len, fs::WriteOption::Flush)) && R_SUCCEEDED(fs::SetFileSize(f, static_cast<s64>(len)));
        static_cast<void>(fs::FlushFile(f));
        fs::CloseFile(f);
        if (!ok) {
            Log("hosts: writing %s failed", path);
            return;
        }
        g_last_block_hash = hash;
        ReloadAtmosphereHosts();
        Log("hosts: %d tailnet names in %s", count, path);
    }

}

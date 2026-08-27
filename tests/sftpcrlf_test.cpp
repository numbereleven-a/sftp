// sftpcrlf_test.cpp — reproduces the NATIVE SFTP/SCP text-mode upload of
// SftpTransfer.cpp (pre-pass size accounting + upload loop) against the
// CURRENT production logic:
//   * pre-pass : CountCrLfToLf (stateful) + trailing lone CR counted
//   * loop     : CrLfToLfStateful per read-buffer (cross-chunk CRLF state)
//   * tail     : trailing lone CR flushed after the loop
// The two converter functions are copied VERBATIM from src/core/ScpTransfer.cpp.
// Checks: declared size == bytes sent, and sent bytes == reference conversion.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>

// ---- verbatim from ScpTransfer.cpp (CountCrLfToLf) ----
static void CountCrLfToLf(const char* data, size_t len, bool& pendingCr, int64_t& total)
{
    size_t kept = 0;
    size_t i = 0;
    if (pendingCr) {
        pendingCr = false;
        ++kept;
        if (len > 0 && data[0] == '\n') { i = 1; }
    }
    for (; i < len; ++i) {
        if (data[i] == '\r' && i + 1 < len && data[i + 1] == '\n')
            continue;
        if (data[i] == '\r' && i + 1 == len) {
            pendingCr = true;
            continue;
        }
        ++kept;
    }
    total += static_cast<int64_t>(kept);
}

// ---- verbatim from ScpTransfer.cpp (CrLfToLfStateful) ----
static size_t CrLfToLfStateful(const char* in, size_t len, char* out, bool& pendingCr)
{
    size_t o = 0;
    size_t i = 0;
    if (pendingCr) {
        pendingCr = false;
        if (len > 0 && in[0] == '\n') {
            out[o++] = '\n';
            i = 1;
        } else {
            out[o++] = '\r';
        }
    }
    for (; i < len; ++i) {
        const char ch = in[i];
        if (ch == '\r') {
            if (i + 1 < len) {
                if (in[i + 1] == '\n') continue;
            } else {
                pendingCr = true;
                continue;
            }
        }
        out[o++] = ch;
    }
    return o;
}

// Reference: whole-buffer CRLF->LF (lone CRs preserved).
static std::string RefConvert(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\r' && i + 1 < in.size() && in[i + 1] == '\n') continue;
        out += in[i];
    }
    return out;
}

struct Sim { int64_t declared = 0, sent = 0; std::string bytes; };

// Mirrors the current production SftpTransfer upload path (pre-pass + loop + tail).
static Sim SimulateNativeSftpUpload(const std::string& content, size_t chunk) {
    Sim r;
    // ---- pre-pass (SftpTransfer.cpp, fixed) ----
    bool pendingCr = false;
    int64_t convertedTotal = 0;
    for (size_t off = 0; off < content.size(); off += chunk) {
        size_t n = (std::min)(chunk, content.size() - off);
        CountCrLfToLf(content.data() + off, n, pendingCr, convertedTotal);
    }
    if (pendingCr) ++convertedTotal;   // trailing lone CR (fixed pre-pass)
    r.declared = convertedTotal;

    // ---- upload loop (SftpTransfer.cpp, fixed: stateful conversion) ----
    pendingCr = false;
    std::vector<char> convBuf(chunk + 16);
    for (size_t off = 0; off < content.size(); off += chunk) {
        size_t n = (std::min)(chunk, content.size() - off);
        size_t dataLen = CrLfToLfStateful(content.data() + off, n, convBuf.data(), pendingCr);
        r.bytes.append(convBuf.data(), dataLen);
        r.sent += (int64_t)dataLen;
    }
    if (pendingCr) { r.bytes += '\r'; r.sent += 1; }   // tail flush (fixed)
    return r;
}

static std::string ShowEsc(const std::string& s) {
    std::string o;
    for (char ch : s) {
        if (ch == '\r') o += "\\r";
        else if (ch == '\n') o += "\\n";
        else o += ch;
    }
    return o;
}

int main() {
    struct Case { const char* label; const char* content; };
    const Case cases[] = {
        { "CRLF within one chunk (chunk big)", "a\r\nb\r\nc\r\n" },
        { "CRLF split across boundary",        "ab\r\ncd" },
        { "lone CR at boundary",               "ab\rcd" },
        { "CR LF CR LF at boundary",           "xy\r\n\r\nzw" },
        { "TRAILING LONE CR",                  "data line\r" },
        { "TRAILING LONE CR after CRLF",       "a\r\nb\r" },
        { "double CR at end",                  "a\r\r" },
        { "single CR only",                    "\r" },
        { "empty",                             "" },
    };
    const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 16, 4096 };
    int failures = 0;
    for (const auto& c : cases) {
        bool bad = false;
        for (size_t ch : chunks) {
            Sim r = SimulateNativeSftpUpload(c.content, ch);
            std::string ref = RefConvert(c.content);
            if (r.bytes != ref || r.declared != r.sent) bad = true;
        }
        Sim r = SimulateNativeSftpUpload(c.content, 3);
        std::string ref = RefConvert(c.content);
        printf("[%s] %-34s chunk=3 decl=%lld sent=%lld bytes=%s expect=%s\n",
               bad ? "BUG " : "OK  ", c.label,
               (long long)r.declared, (long long)r.sent,
               ShowEsc(r.bytes).c_str(), ShowEsc(ref).c_str());
        if (bad) ++failures;
    }
    printf("\n%s (%d failing)\n", failures ? "FAILED" : "ALL OK", failures);
    return failures ? 1 : 0;
}

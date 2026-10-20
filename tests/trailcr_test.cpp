// trailcr_test.cpp — reproduces the SCP upload size-accounting of
// ShellFallbackTransfer.cpp (pre-pass CountCrLfToLf + send-loop CrLfToLfStateful
// + trailing-CR flush) and checks that the declared size equals the bytes sent.
// The converter functions are linked from production ScpTransfer.cpp
// (CountCrLfToLf / CrLfToLfStateful, shared helpers). "fixed" mode mirrors the
// current production pre-pass (counts the trailing lone CR); "pre-fix" mode
// mirrors the old pre-pass (does not).
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

// ---- verbatim from ShellFallbackTransfer.cpp:777 ----
void CountCrLfToLf(const char*, size_t, bool&, int64_t&);

// ---- verbatim from ShellFallbackTransfer.cpp:801 ----
size_t CrLfToLfStateful(const char*, size_t, char*, bool&);

// Reference: whole-buffer CRLF->LF (lone CRs preserved).
static std::string RefConvert(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\r' && i + 1 < in.size() && in[i + 1] == '\n') continue;
        out += in[i];
    }
    return out;
}

static int failures = 0;

// Reproduce the EXACT production size accounting for one upload of `content`,
// read in chunks of `chunk` (like ReadFile SFTP_SCP_BLOCK_SIZE reads).
struct Result { int64_t declaredSize = 0; int64_t bytesSent = 0; std::string sent; std::string expected; bool match = true; };

static Result SimulateUpload(const std::string& content, size_t chunk, bool fixed = false) {
    Result r;
    // ---- pre-pass (ShellFallbackTransfer.cpp:884-888) ----
    int64_t convertedTotal = 0;
    bool pendingCr = false;
    for (size_t off = 0; off < content.size(); off += chunk) {
        size_t n = (std::min)(chunk, content.size() - off);
        CountCrLfToLf(content.data() + off, n, pendingCr, convertedTotal);
    }
    if (fixed && pendingCr) ++convertedTotal;  // PROPOSED FIX: count the trailing CR the send-loop will flush
    pendingCr = false;                 // line 887 (verbatim)
    r.declaredSize = convertedTotal;   // line 888 (verbatim)

    // ---- send-loop (ShellFallbackTransfer.cpp:904-926) ----
    pendingCr = false;
    std::vector<char> encBuf(chunk + 16);
    for (size_t off = 0; off < content.size(); off += chunk) {
        size_t n = (std::min)(chunk, content.size() - off);
        size_t sendLen = CrLfToLfStateful(content.data() + off, n, encBuf.data(), pendingCr);
        r.sent.append(encBuf.data(), sendLen);   // ScpWriteAll(sendBuf, sendLen)
        r.bytesSent += (int64_t)sendLen;
    }
    if (pendingCr) { r.sent += '\r'; r.bytesSent += 1; }   // lines 919-926 (verbatim)

    r.expected = RefConvert(content);
    r.match = (r.declaredSize == r.bytesSent) && (r.sent == r.expected);
    return r;
}

int main() {
    struct Case { const char* label; const char* content; };
    const Case cases[] = {
        { "plain (no CR)",                "hello world\nline2\n" },
        { "CRLF lines",                   "a\r\nb\r\nc\r\n" },
        { "TRAILING LONE CR",             "data line\r" },
        { "TRAILING LONE CR after CRLF",  "a\r\nb\r" },
        { "lone CR mid-file",             "a\rb\rc\n" },
        { "CR then LF (CRLF) at end",     "a\r\n" },
        { "double CR at end",             "a\r\r" },
        { "single CR only",               "\r" },
        { "empty",                        "" },
    };
    const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 16, 4096 };

    int fixedFailures = 0;
    for (const auto& c : cases) {
        bool anyMismatch = false, anyFixedMismatch = false;
        for (size_t ch : chunks) {
            if (!SimulateUpload(c.content, ch, /*fixed=*/false).match) anyMismatch = true;
            if (!SimulateUpload(c.content, ch, /*fixed=*/true).match) anyFixedMismatch = true;
        }
        Result r = SimulateUpload(c.content, 3, /*fixed=*/false);
        Result rf = SimulateUpload(c.content, 3, /*fixed=*/true);
        printf("[%s] %-28s cur: decl=%lld sent=%lld | fixed: decl=%lld sent=%lld  %s\n",
               r.match ? "OK  " : "BUG ", c.label,
               (long long)r.declaredSize, (long long)r.bytesSent,
               (long long)rf.declaredSize, (long long)rf.bytesSent,
               anyMismatch ? "<== MISMATCH (current)" : "");
        if (anyMismatch) ++failures;
        if (anyFixedMismatch) ++fixedFailures;
    }
    printf("\npre-fix  logic (before):  %s (%d failing groups)\n", failures ? "FAILED (as expected)" : "ALL OK", failures);
    printf("current production (fixed): %s (%d failing groups)\n", fixedFailures ? "FAILED" : "ALL OK", fixedFailures);
    return fixedFailures ? 1 : 0;
}

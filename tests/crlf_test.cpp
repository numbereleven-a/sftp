// crlf_test.cpp — verifies CountCrLfToLf / CrLfToLfStateful agree with each
// other and with the naive whole-buffer ConvertCrLfToLf semantics, including
// CR/LF pairs split across chunk boundaries.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

struct CrLfState { bool pendingCr = false; int64_t total = 0; };

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
        if (data[i] == '\r' && i + 1 < len && data[i + 1] == '\n') continue;
        if (data[i] == '\r' && i + 1 == len) { pendingCr = true; continue; }
        ++kept;
    }
    total += static_cast<int64_t>(kept);
}

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

// Reference: whole-buffer conversion (no chunking).
static std::string RefConvert(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\r' && i + 1 < in.size() && in[i + 1] == '\n') continue;
        out += in[i];
    }
    return out;
}

static int failures = 0;

static void RunCase(const std::string& content, size_t chunkSize) {
    // Counting pass
    CrLfState cs;
    for (size_t off = 0; off < content.size(); off += chunkSize)
        CountCrLfToLf(content.data() + off,
                      (std::min)(chunkSize, content.size() - off), cs.pendingCr, cs.total);
    if (cs.pendingCr) ++cs.total;   // trailing lone CR flushed at EOF

    // Conversion pass
    std::vector<char> inBuf(content.begin(), content.end());
    std::vector<char> outBuf(content.size() + 16);
    std::string converted;
    bool pendingCr = false;
    for (size_t off = 0; off < content.size(); off += chunkSize) {
        size_t n = (std::min)(chunkSize, content.size() - off);
        size_t outLen = CrLfToLfStateful(inBuf.data() + off, n, outBuf.data(), pendingCr);
        converted.append(outBuf.data(), outLen);
    }
    if (pendingCr) converted += '\r';

    const std::string ref = RefConvert(content);
    const bool okCount = (cs.total == (int64_t)ref.size());
    const bool okConv  = (converted == ref);
    if (!okCount || !okConv) {
        printf("FAIL chunk=%zu content=%s\n", chunkSize, content.c_str());
        printf("  counted=%lld ref=%zu\n", (long long)cs.total, ref.size());
        printf("  converted(%zu) vs ref(%zu)\n", converted.size(), ref.size());
        ++failures;
    }
}

int main() {
    const char* contents[] = {
        "a\r\nb\r\nc",
        "\r\nstart",
        "end\r\n",
        "lone\rcr\n",
        "split\r",
        "split\r\n",           // CRLF split across chunks when chunk=6? handled by cases below
        "\r\r\n\n\r\n",
        "plain ascii text only",
        "",
        "\r",
        "\r\n",
    };
    const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 16, 1024 };
    for (const auto* c : contents)
        for (size_t ch : chunks)
            RunCase(c, ch);

    // Explicit split-CRLF case: "abc\r\nxyz" with chunk=4 → boundary between \r and \n
    {
        const std::string s = "abc\r\nxyz";
        CrLfState cs;
        CountCrLfToLf(s.data(), 4, cs.pendingCr, cs.total);   // "abc\r"
        CountCrLfToLf(s.data() + 4, s.size() - 4, cs.pendingCr, cs.total); // "\nxyz"
        if (cs.pendingCr) ++cs.total;
        if (cs.total != (int64_t)RefConvert(s).size()) { printf("FAIL explicit split count\n"); ++failures; }
    }

    printf(failures ? "FAILED %d cases\n" : "ALL OK (%d failures)\n", failures);
    return failures ? 1 : 0;
}

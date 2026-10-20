#include <windows.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <climits>

int ConvertCrToCrLf(LPSTR data, size_t len, size_t capacity, bool* pLastWasCr)
{
    if (!data || !pLastWasCr || len > capacity)
        return 0;

    bool lastWasCr = *pLastWasCr;
    std::string result;
    result.reserve(len + len / 2); // worst case expansion

    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\r') {
            lastWasCr = true;
            result.push_back('\r');
        } else if (c == '\n') {
            if (!lastWasCr)
                result.push_back('\r');
            result.push_back('\n');
            lastWasCr = false;
        } else {
            lastWasCr = false;
            result.push_back(c);
        }
    }

    if (result.size() > capacity || result.size() > INT_MAX)
        return -1;
    *pLastWasCr = lastWasCr;
    memcpy(data, result.data(), result.size());
    return static_cast<int>(result.size());
}

int ConvertCrLfToLf(LPSTR data, size_t len)
{
    if (!data || len == 0)
        return 0;

    size_t out = 0;
    for (size_t i = 0; i < len; ++i) {
        const char ch = data[i];
        if (ch == '\r' && i + 1 < len && data[i + 1] == '\n') {
            continue;
        }
        data[out++] = ch;
    }
    return static_cast<int>(out);
}

// Counts the CRLF->LF output size of a chunk, carrying a pending lone CR
// from the previous chunk (see CrLfToLfStateful). total accumulates the kept
// byte count; a still-pending CR at the end is NOT included here, so callers
// must add 1 if pendingCr is true after the final chunk.
void CountCrLfToLf(const char* data, size_t len, bool& pendingCr, int64_t& total)
{
    size_t kept = 0;
    size_t i = 0;
    if (pendingCr) {
        pendingCr = false;
        ++kept;                       // lone CR from previous chunk…
        if (len > 0 && data[0] == '\n') { i = 1; }  // …unless it pairs here
    }
    for (; i < len; ++i) {
        if (data[i] == '\r' && i + 1 < len && data[i + 1] == '\n')
            continue;                 // drop CR of an in-buffer CRLF
        if (data[i] == '\r' && i + 1 == len) {
            pendingCr = true;         // may pair with the next chunk
            continue;
        }
        ++kept;
    }
    total += static_cast<int64_t>(kept);
}

// Converts one chunk with cross-chunk CRLF state. Separate in/out buffers,
// so no in-place aliasing hazards; outCap must be >= len + 1 (worst case:
// carried lone CR followed by a chunk with nothing dropped).
size_t CrLfToLfStateful(const char* in, size_t len, char* out, bool& pendingCr)
{
    size_t o = 0;
    size_t i = 0;
    if (pendingCr) {
        pendingCr = false;
        if (len > 0 && in[0] == '\n') {
            out[o++] = '\n';           // complete the split CRLF: keep the LF
            i = 1;
        } else {
            out[o++] = '\r';           // previous chunk ended with a lone CR
        }
    }
    for (; i < len; ++i) {
        const char ch = in[i];
        if (ch == '\r') {
            if (i + 1 < len) {
                if (in[i + 1] == '\n') continue;   // drop CR of an in-buffer CRLF
            } else {
                pendingCr = true;                  // may pair with the next chunk
                continue;
            }
        }
        out[o++] = ch;
    }
    return o;
}

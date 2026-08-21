#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>

// Copy of PhpNormalizeRel from PhpAgentClient.cpp (algorithm-parity test).
static std::string PhpNormalizeRel(const std::string& in)
{
    std::string p = in;
    p.erase(std::remove(p.begin(), p.end(), '\0'), p.end());
    std::replace(p.begin(), p.end(), '\\', '/');
    const auto isPhpSpace = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0 || c == '\x0B';
    };
    size_t b = 0, e = p.size();
    while (b < e && isPhpSpace((unsigned char)p[b])) ++b;
    while (e > b && isPhpSpace((unsigned char)p[e - 1])) --e;
    p = p.substr(b, e - b);
    if (p.empty() || p == ".") return ".";
    size_t start = p.find_first_not_of('/');
    if (start == std::string::npos) return ".";
    p.erase(0, start);
    std::vector<std::string> parts;
    size_t i = 0;
    while (i <= p.size()) {
        size_t sl = p.find('/', i);
        if (sl == std::string::npos) sl = p.size();
        const std::string part = p.substr(i, sl - i);
        if (!part.empty() && part != ".") {
            if (part == "..") { if (!parts.empty()) parts.pop_back(); }
            else parts.push_back(part);
        }
        i = sl + 1;
    }
    if (parts.empty()) return ".";
    std::string out;
    for (const auto& s : parts) { if (!out.empty()) out += '/'; out += s; }
    return out;
}

static void printB64(const std::string& s) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    for (; i + 2 < s.size(); i += 3) {
        unsigned v = (unsigned char)s[i] << 16 | (unsigned char)s[i+1] << 8 | (unsigned char)s[i+2];
        printf("%c%c%c%c", t[(v>>18)&63], t[(v>>12)&63], t[(v>>6)&63], t[v&63]);
    }
    if (i + 1 == s.size()) {
        unsigned v = (unsigned char)s[i] << 16;
        printf("%c%c==", t[(v>>18)&63], t[(v>>12)&63]);
    } else if (i + 2 == s.size()) {
        unsigned v = (unsigned char)s[i] << 16 | (unsigned char)s[i+1] << 8;
        printf("%c%c%c=", t[(v>>18)&63], t[(v>>12)&63], t[(v>>6)&63]);
    }
    printf("\n");
}

int main() {
    const char* cases[] = {
        "a/b/c", "a\\b\\c", "/a/../b", "a/./b", "..", "../x", "a/..", "",
        ".", "//", "a//b", " a/b\t ", "a/b/../../c", "docs/report..final.docx",
        "\xD0\xB4\xD0\xBE\xD0\xBA/sub", "../../etc/passwd", "/../../", "x/..//y",
    };
    for (const char* c : cases) printB64(PhpNormalizeRel(c));
    return 0;
}

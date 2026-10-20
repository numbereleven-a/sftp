// Emits production request-signing headers for the isolated HTTP regression test.
#include "global.h"
#include "PhpRequestSigning.h"
#include <iostream>
#include <iterator>
#include <io.h>
#include <fcntl.h>

int main(int argc, char** argv) {
    _setmode(_fileno(stdin), _O_BINARY);
    if (argc != 3) return 2;
    const char* password = getenv("TC_SFTP_AGENT_PSK");
    if (!password) return 2;
    const char* salt = getenv("SFTP_TEST_SALT");
    const std::string body(std::istreambuf_iterator<char>(std::cin), {});
    const std::string target = argv[2];
    const auto start = target.find("op=");
    if (start == target.npos) return 2;
    const auto end = target.find('&', start);
    const auto result = SignPhpRequest(password, salt ? salt : "", argv[1],
        target.substr(start + 3, end - start - 3), target, RequestDigest::memory(body.data(), body.size()));
    if (result.empty()) return 1;
    std::cout << result;
    return 0;
}

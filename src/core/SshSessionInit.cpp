#include "global.h"
#include "global.h"
#include <windows.h>
#include "HostFingerprint.h"
#include <cerrno>
#include <array>
#include <memory>
#include <format>
#include <string>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "SshBackendFactory.h"
#include "PluginEntryPoints.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "IUserFeedback.h"
#include "ITransportStream.h"
#include "SshSessionInit.h"

static LPVOID session_alloc(size_t count, LPVOID* /*abstract*/)
{
    return malloc(count);
}

static LPVOID session_realloc(LPVOID ptr, size_t count, LPVOID* /*abstract*/)
{
    return realloc(ptr, count);
}

static void session_free(LPVOID ptr, LPVOID* /*abstract*/)
{
    free(ptr);
}

// ---------------------------------------------------------------------------
// Custom SEND/RECV callbacks for transport-backed sessions (ProxyJump).
// These are installed before startup() when cs->transport_stream is set.
// The session abstract is the pConnectSettings pointer (set at createSession).
// ---------------------------------------------------------------------------
static ssize_t transport_send_cb(
    libssh2_socket_t /*sock*/,
    const void* buffer, size_t length,
    int /*flags*/,
    void** abstract)
{
    auto* cs = static_cast<tConnectSettings*>(*abstract);
    ssize_t rc = cs->transport_stream->write(buffer, length);
    if (rc == ITRANSPORT_EAGAIN)
        return -EAGAIN;
    return rc;
}

static ssize_t transport_recv_cb(
    libssh2_socket_t /*sock*/,
    void* buffer, size_t length,
    int /*flags*/,
    void** abstract)
{
    auto* cs = static_cast<tConnectSettings*>(*abstract);
    ssize_t rc = cs->transport_stream->read(buffer, length);
    if (rc == ITRANSPORT_EAGAIN)
        return -EAGAIN;
    return rc;
}

int InitializeSshSession(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    std::unique_ptr<ISshBackend>& backend)
{
    std::array<char, 1024> buf{};
    progress = 30; // PROG_SESSION_INIT
    LoadStr(buf, IDS_INITSSH2);
    if (ProgressProc(PluginNumber, buf.data(), "-", progress))
        return -50;

    if (!backend)
        backend = CreateSshBackend();
    {
        auto sessionPtr = backend->createSession(session_alloc, session_free, session_realloc, ConnectSettings);
        if (!sessionPtr) {
            ShowErrorId(IDS_ERR_INIT_SSH2);
            if (LogProc) LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, "SFTP: SSH library session init failed");
            return -60;
        }
        ConnectSettings->session = std::move(sessionPtr);
    }

    ConnectSettings->session->setBlocking(0);

    // If we have a transport stream (ProxyJump), install custom SEND/RECV
    // callbacks so that libssh2 routes all I/O through the channel rather
    // than the underlying TCP socket directly.
    if (ConnectSettings->transport_stream) {
        ConnectSettings->session->callbackSet(
            LIBSSH2_CALLBACK_SEND, reinterpret_cast<void*>(transport_send_cb));
        ConnectSettings->session->callbackSet(
            LIBSSH2_CALLBACK_RECV, reinterpret_cast<void*>(transport_recv_cb));
        ShowStatus(("Transport: " + std::string(ConnectSettings->transport_stream->describe())).c_str());
    }

    loop = 30;
    LoadStr(buf, IDS_SET_COMPRESSION);
    LPCSTR ses_prefs = ConnectSettings->compressed ? "zlib,none" : "none";
    int err;
    while ((err = ConnectSettings->session->methodPref(LIBSSH2_METHOD_COMP_CS, ses_prefs)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
            break;
        WaitForTransportReadable(ConnectSettings);
    }
    SftpLogLastError("libssh2_session_method_pref: ", err);

    while ((err = ConnectSettings->session->methodPref(LIBSSH2_METHOD_COMP_SC, ses_prefs)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
            break;
        WaitForTransportReadable(ConnectSettings);
    }
    SftpLogLastError("libssh2_session_method_pref2: ", err);

    progress = 40; // PROG_SESSION_STARTUP
    LoadStr(buf, IDS_SESSION_STARTUP);
    int auth;
    const ULONGLONG deadline = GetTickCount64() + 30000;
    while ((auth = ConnectSettings->session->startup((int)ConnectSettings->sock)) == LIBSSH2_ERROR_EAGAIN) {
        if (GetTickCount64() >= deadline) { auth = LIBSSH2_ERROR_TIMEOUT; break; }
        if (ProgressLoop(buf.data(), progress, progress + 20, &loop, &lasttime))
            break;
        WaitForTransportReadable(ConnectSettings);
    }

    if (auth) {
        char* errmsg;
        int errmsg_len;
        ConnectSettings->session->lastError(&errmsg, &errmsg_len, false);
        ShowErrorId(IDS_ERR_SSH_SESSION, errmsg);
        if (LogProc) {
            const std::string msg = std::format("SFTP: SSH handshake failed: {}", errmsg ? errmsg : "(no details)");
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return -70;
    }
    SftpLogLastError("libssh2_session_startup: ", ConnectSettings->session->lastErrno());
    return 0;
}

int VerifyServerFingerprint(pConnectSettings ConnectSettings)
{
    const std::string fingerprintHex = Sha256HostFingerprint(ConnectSettings->session.get());
    if (fingerprintHex.empty()) return -90;
    const std::string endpoint = ConnectSettings->server + ":" + std::to_string(ConnectSettings->customport);
    std::array<char, 1024> savedEndpoint{};
    GetPrivateProfileString(ConnectSettings->DisplayName.c_str(), "fingerprinthost", "",
        savedEndpoint.data(), static_cast<DWORD>(savedEndpoint.size()), ConnectSettings->IniFileName.c_str());
    if (savedEndpoint[0] && endpoint != savedEndpoint.data()) {
        if (ConnectSettings->feedback) ConnectSettings->feedback->ShowError("The saved host key belongs to a different host or port.");
        return -100;
    }
    const bool legacyMatch = MatchesLegacyFingerprint(ConnectSettings->session.get(), ConnectSettings->savedfingerprint);
    if (legacyMatch) ConnectSettings->savedfingerprint.clear();
    ShowStatus(fingerprintHex.c_str());

    if (ConnectSettings->savedfingerprint != fingerprintHex) {
        std::array<char, 4 * MAX_PATH> msg1{};
        std::array<char, MAX_PATH> msg2{};
        if (ConnectSettings->savedfingerprint.empty())
            LoadStr(msg1, IDS_CONNECTION_FIRSTTIME);
        else
            LoadStr(msg1, IDS_FINGERPRINT_CHANGED);
        LoadStr(msg2, IDS_FINGERPRINT);
        const std::string prompt = std::string(msg1.data()) + msg2.data() + fingerprintHex;

        if (!ConnectSettings->savedfingerprint.empty()) {
            if (ConnectSettings->feedback) ConnectSettings->feedback->ShowError(prompt.c_str());
            return -100;
        }
        bool verified = legacyMatch;
        if (!verified && ConnectSettings->feedback) {
            verified = ConnectSettings->feedback->AskYesNo(prompt.c_str(), "SFTP Security Warning");
        }

        if (!verified)
            return -100;

        WritePrivateProfileString(ConnectSettings->DisplayName.c_str(), "fingerprint", fingerprintHex.c_str(), ConnectSettings->IniFileName.c_str());
        WritePrivateProfileString(ConnectSettings->DisplayName.c_str(), "fingerprinthost",
            endpoint.c_str(), ConnectSettings->IniFileName.c_str());
        ConnectSettings->savedfingerprint = fingerprintHex;
    }
    return 0;
}

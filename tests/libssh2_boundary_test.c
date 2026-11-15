/* Exercise the actual packet parsers with synthetic peer replies. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef SFTP_IMPLEMENTATION
#define SFTP_IMPLEMENTATION "../thirdparty/libssh2/src/sftp.c"
#endif
#ifndef TRANSPORT_IMPLEMENTATION
#define TRANSPORT_IMPLEMENTATION "../thirdparty/libssh2/src/transport.c"
#endif
#include SFTP_IMPLEMENTATION
#include TRANSPORT_IMPLEMENTATION

static void *guard_alloc(size_t size, void **abstract)
{
    size_t aligned = (size + 15) & ~(size_t)15;
    size_t pages = (aligned + 4095) & ~(size_t)4095;
    unsigned char *base = VirtualAlloc(NULL, pages + 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD old;
    (void)abstract;
    if(!base) return NULL;
    VirtualProtect(base + pages, 4096, PAGE_NOACCESS, &old);
    return base + pages - aligned;
}
static int double_free_count = 0;
static void *last_freed_ptr = NULL;
static void guard_free(void *ptr, void **abstract)
{
    MEMORY_BASIC_INFORMATION info;
    (void)abstract;
    if(ptr && ptr == last_freed_ptr)
        ++double_free_count;
    last_freed_ptr = ptr;
    if(ptr && VirtualQuery(ptr, &info, sizeof(info))) VirtualFree(info.AllocationBase, 0, MEM_RELEASE);
}
static void *guard_realloc(void *ptr, size_t size, void **abstract)
{
    (void)ptr; (void)size; (void)abstract;
    return NULL; /* These parser cases do not reallocate. */
}

static int name_reply(const char *which)
{
    LIBSSH2_SESSION *session = libssh2_session_init_ex(guard_alloc, guard_free, guard_realloc, NULL);
    LIBSSH2_CHANNEL channel = {0};
    LIBSSH2_SFTP sftp = {0};
    LIBSSH2_SFTP_PACKET *packet = guard_alloc(sizeof(*packet), NULL);
    unsigned char *data;
    char target[256] = {0};
    int rc, expected = 3;
    size_t len = 16;
    int status = !strncmp(which, "status", 6);
    uint32_t id = !strcmp(which, "status-error") ? 0 : 7;
    if(status) len = 9;
    data = guard_alloc(len, NULL);
    memset(data, 0, len);
    data[0] = status ? SSH_FXP_STATUS : SSH_FXP_NAME;
    _libssh2_htonu32(data + 1, id);
    if(status) {
        _libssh2_htonu32(data + 5, !strcmp(which, "status-error") ? LIBSSH2_FX_PERMISSION_DENIED : LIBSSH2_FX_OK);
        expected = !strcmp(which, "status-error") ? LIBSSH2_ERROR_SFTP_PROTOCOL : 0;
    }
    else {
        _libssh2_htonu32(data + 5, 1);
        _libssh2_htonu32(data + 9, !strcmp(which, "malformed-name") ? 128 : 3);
        memcpy(data + 13, "abc", 3);
        if(!strcmp(which, "malformed-name")) expected = LIBSSH2_ERROR_SFTP_PROTOCOL;
    }
    channel.session = session;
    session->socket_state = LIBSSH2_SOCKET_CONNECTED;
    sftp.channel = &channel;
    sftp.version = 3;
    sftp.symlink_state = libssh2_NB_state_sent;
    sftp.symlink_request_id = id;
    _libssh2_list_init(&sftp.packets);
    memset(packet, 0, sizeof(*packet));
    packet->request_id = id;
    packet->data = data;
    packet->data_len = len;
    _libssh2_list_add(&sftp.packets, &packet->node);
    rc = sftp_symlink(&sftp, "x", 1, target, sizeof(target), LIBSSH2_SFTP_REALPATH);
    if(rc != expected || (!status && expected == 3 && strcmp(target, "abc")) ||
       (!strcmp(which, "status-error") && sftp.last_errno != LIBSSH2_FX_PERMISSION_DENIED)) {
        fprintf(stderr, "FAIL %s rc=%d expected=%d\n", which, rc, expected);
        return 1;
    }
    session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
    libssh2_session_free(session);
    printf("PASS %s\n", which);
    return 0;
}

static int mac_hash(LIBSSH2_SESSION *session, unsigned char *buf, uint32_t seq,
                    const unsigned char *packet, size_t len, const unsigned char *extra,
                    size_t extra_len, void **abstract)
{
    (void)session; (void)seq; (void)packet; (void)len; (void)extra; (void)extra_len; (void)abstract;
    memset(buf, 0, 4); return 0;
}
static int crypt_copy(LIBSSH2_SESSION *session, unsigned int seq, unsigned char *block,
                      size_t len, void **abstract, int firstlast)
{
    (void)session; (void)seq; (void)abstract; (void)firstlast;
    /* Touch the entire block as a real cipher would. Guard pages expose an OOB read. */
    volatile unsigned char last = block[len - 1];
    (void)last;
    return 0;
}
static int short_etm(void)
{
    LIBSSH2_SESSION *session = libssh2_session_init_ex(guard_alloc, guard_free, guard_realloc, NULL);
    LIBSSH2_MAC_METHOD mac = {0};
    LIBSSH2_CRYPT_METHOD cipher = {0};
    int rc;
    mac.mac_len = 4; mac.etm = 1; mac.hash = mac_hash;
    cipher.blocksize = 16; cipher.crypt = crypt_copy;
    session->remote.mac = &mac;
    session->remote.crypt = &cipher;
    session->packet.packet_length = 1;
    session->packet.total_num = 9;
    session->packet.payload = guard_alloc(9, NULL);
    memset(session->packet.payload, 0, 9);
    double_free_count = 0;
    last_freed_ptr = NULL;
    rc = fullpacket(session, 1);
    session->remote.mac = NULL;
    session->remote.crypt = NULL;
    libssh2_session_free(session);
    if(double_free_count != 0) {
        fprintf(stderr, "FAIL short-etm: double_free_count=%d\n", double_free_count);
        return 1;
    }
    printf("%s short-etm\n", rc == LIBSSH2_ERROR_DECRYPT ? "PASS" : "FAIL");
    return rc == LIBSSH2_ERROR_DECRYPT ? 0 : 1;
}
int main(int argc, char **argv)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if(argc != 2) return 2;
    if(!strcmp(argv[1], "short-etm")) return short_etm();
    if(!strcmp(argv[1], "ext-info")) {
        LIBSSH2_SESSION *session = libssh2_session_init_ex(guard_alloc, guard_free, guard_realloc, NULL);
        unsigned char *data = guard_alloc(5, NULL);
        DWORD start = GetTickCount();
        data[0] = SSH_MSG_EXT_INFO;
        _libssh2_htonu32(data + 1, UINT32_MAX);
        _libssh2_packet_add(session, data, 5, LIBSSH2_MAC_CONFIRMED, 0);
        if(GetTickCount() - start > 1000) return 1;
        libssh2_session_free(session);
        puts("PASS ext-info");
        return 0;
    }
    return name_reply(argv[1]);
}

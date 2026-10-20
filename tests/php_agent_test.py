"""Exercise signed HTTP requests against an isolated production PHP agent."""
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlencode


def main():
    php = sys.argv[1]
    source = Path(__file__).resolve().parents[1] / 'src' / 'agent' / 'sftp.php'
    with tempfile.TemporaryDirectory(prefix='sftp-agent-test-') as directory:
        root = Path(directory)
        script = source.read_text(encoding='utf-8-sig')
        password = secrets.token_hex(24)
        salt = secrets.token_hex(16) if '--hash-only' in sys.argv else ''
        key_material = salt + ':' + password if salt else password
        key = hashlib.sha256(key_material.encode()).hexdigest().encode()
        if salt:
            script = script.replace("const AGENT_PSK_SALT = '';", "const AGENT_PSK_SALT = '" + salt + "';")
            script = script.replace("const AGENT_PSK_SHA256 = '';", "const AGENT_PSK_SHA256 = '" + key.decode() + "';")
        (root / 'sftp.php').write_text(script, encoding='utf-8')
        env = os.environ.copy()
        if not salt:
            env['TC_SFTP_AGENT_PSK'] = password
        else:
            for name in ('TC_SFTP_AGENT_PSK', 'SFTP_AGENT_PSK', 'AGENT_PSK'):
                env.pop(name, None)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        server = subprocess.Popen([php, '-S', f'127.0.0.1:{port}', '-t', directory],
                                  env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)

            def headers(method, target, body=b''):
                signer = next((arg for arg in sys.argv[2:] if not arg.startswith('--')), None)
                if signer:
                    signer_env = os.environ.copy()
                    signer_env['TC_SFTP_AGENT_PSK'] = password
                    signer_env['SFTP_TEST_SALT'] = salt
                    result = subprocess.run([signer, method, target], input=body, env=signer_env,
                                            capture_output=True, check=True)
                    return dict(line.split(': ', 1) for line in result.stdout.decode().splitlines() if ': ' in line)
                op = target.split('op=')[1].split('&')[0]
                stamp, nonce = str(int(time.time())), secrets.token_hex(16)
                material = '\n'.join([method, op, target, stamp, nonce, hashlib.sha256(body).hexdigest()])
                return {'X-SFTP-TS': stamp, 'X-SFTP-NONCE': nonce,
                        'X-SFTP-SIGNATURE-VERSION': '2',
                        'X-SFTP-SIGNATURE': hmac.new(key, material.encode(), hashlib.sha256).hexdigest()}

            def request(op, body=b'', signed=True, extra=None, auth=None, method='POST'):
                target = '/sftp.php?' + urlencode({'op': op, **(extra or {})})
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                connection.request(method, target, body, auth if auth is not None else
                                   (headers(method, target, body) if signed else {}))
                response = connection.getresponse()
                result = response.status, response.read()
                connection.close()
                return result

            def check(condition, message):
                if not condition:
                    raise AssertionError(message)
                print('PASS', message)

            code, body = request('PROBE', signed=False, method='GET')
            check(code == 200 and json.loads(body)['capabilities']['auth']['signature_version'] == 2,
                  'public probe exposed only negotiation data')
            check(request('LIST', signed=False)[0] == 401, 'unsigned request rejected')
            check(request('LIST', auth={'X-SFTP-AUTH': password})[0] == 401, 'bearer-only request rejected')
            target = '/sftp.php?op=LIST'
            auth = headers('POST', target)
            check(request('LIST', auth=auth)[0] == 200, 'signed listing succeeded')
            check(request('LIST', auth=auth)[0] == 401, 'replay rejected')
            auth = headers('POST', '/sftp.php?op=PUT&path=first&offset=0', b'ABC')
            check(request('PUT', b'ABC', extra={'path': 'second', 'offset': 0}, auth=auth)[0] == 401,
                  'changed path rejected')
            auth = headers('POST', '/sftp.php?op=PUT&path=first&offset=0', b'ABC')
            check(request('PUT', b'XYZ', extra={'path': 'first', 'offset': 0}, auth=auth)[0] == 401,
                  'changed body rejected')
            result = request('PUT', b'ABCDEF', extra={'path': 'uploaded.txt', 'offset': 0})
            check(result[0] == 200, 'signed upload succeeded: ' + str(result))
            check(request('FINALIZE', extra={'path': 'uploaded.txt'})[0] == 200 and
                  (root / 'uploaded.txt').read_bytes() == b'ABCDEF', 'finalize succeeded')
            (root / 'retained').mkdir()
            (root / 'retained' / 'child.txt').write_text('keep')
            multipart = b'--boundary\r\nContent-Disposition: form-data; name="recursive"\r\n\r\n1\r\n--boundary--\r\n'
            auth = headers('POST', '/sftp.php?op=RMDIR&path=retained')
            auth['Content-Type'] = 'multipart/form-data; boundary=boundary'
            result = request('RMDIR', multipart, extra={'path': 'retained'}, auth=auth)
            check(result[0] == 400 and (root / 'retained' / 'child.txt').exists(),
                  'multipart parameter injection rejected: HTTP ' + str(result[0]))
            check(request('RMDIR', extra={'path': '.', 'recursive': 1})[0] == 400, 'jail root removal rejected')
            check(request('SHELL_EXEC', extra={'cmd': 'echo test'})[0] == 403, 'shell disabled by default')
            check(request('GET', extra={'path': '../outside'})[0] == 403, 'parent traversal rejected')
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w', format=tarfile.PAX_FORMAT) as tar:
                info = tarfile.TarInfo('nested/' + 'long-name-' * 16 + '.txt')
                info.size = 7
                tar.addfile(info, io.BytesIO(b'payload'))
            check(request('TAR_EXTRACT', archive.getvalue(), extra={'path': 'extracted'})[0] == 200,
                  'bounded PAX extraction succeeded')
            bad = bytearray(archive.getvalue())
            bad[0] ^= 1
            check(request('TAR_EXTRACT', bytes(bad), extra={'path': 'bad'})[0] == 400, 'invalid TAR checksum rejected')
            entry = tarfile.TarInfo('base256.txt')
            entry.size = 7
            block = bytearray(entry.tobuf(format=tarfile.USTAR_FORMAT))
            block[124:136] = ((1 << 95) | 7).to_bytes(12, 'big')
            block[148:156] = b'        '
            block[148:156] = ('%06o\0 ' % sum(block)).encode()
            data = bytes(block) + b'payload' + bytes(505) + bytes(1024)
            result = request('TAR_EXTRACT', data, extra={'path': 'base256'})
            check(result[0] == 200 and
                  (root / 'base256' / 'base256.txt').read_bytes() == b'payload',
                  'base-256 TAR size decoded correctly: ' + str(result))
            with tempfile.TemporaryDirectory(prefix=root.name + '-outside-') as outside:
                outside_path = Path(outside)
                (outside_path / 'secret.txt').write_text('outside-test-marker')
                try:
                    os.symlink(outside_path, root / 'escape', target_is_directory=True)
                except OSError:
                    print('SKIP symlink escape checks: symbolic-link creation unavailable')
                else:
                    check(request('GET', extra={'path': 'escape/secret.txt'})[0] == 403,
                          'read through outward symlink rejected')
                    check(request('PUT', b'new', extra={'path': 'escape/new.txt'})[0] == 403,
                          'write through outward symlink rejected')
            print('All PHP agent checks passed.')
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == '__main__':
    main()

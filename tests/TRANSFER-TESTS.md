# Transfer regressions

Run `run-transfer-tests.ps1` with `-VcVarsPath` pointing to the Visual C++ environment script for the target architecture and `-Architecture x64` or `-Architecture x86`. Windows PowerShell 5.1 is supported.

`download_skip_test.cpp` includes the production download error module and uses real Windows file operations. It tests missing files/directories, locked files, move/resume exclusions, nested batches, reset between operations, and independent transfer threads. The Skip all selection is injected into the operation state; the graphical dialog itself is not clicked by this test.

`lan_transfer_test.cpp` includes the production LAN transfer implementation. A loopback TCP peer returns deterministic transfer replies while the production client reads and writes real files. Tests compare the complete file bytes for resumed, fresh, empty, and already-complete downloads, and exercise successful, empty, whitespace-only, and disconnected upload completion replies. An already-connected socket is injected; pairing, discovery, and credential storage are outside the test scope.

`plugin_load_test.cpp` is a separate smoke test for the compiled plugin. Build it with the matching architecture and the `src/include` include directory, then pass the absolute plugin binary path as its only argument. It checks DLL load/unload, initialization, exported functions, 100 batch callback pairs, and the error-dialog resources.

The runner also builds production text-conversion tests, the LAN3 loopback test, and a PHP signing helper.
LAN3 tests isolate APPDATA and exercise real password/trust authentication, shared-folder restrictions,
file operations, malformed frames, saved profile roles, and shutdown. The old PAIR1 model tests have been
replaced by these production tests.

With `-PhpPath` set to a local PHP executable, the runner starts an isolated loopback PHP agent and
checks the C++ production signer against it. Both plain-environment and hash-only deployed credentials
are exercised. Python must be available as `python.exe` or passed with `-PythonPath`.
No router configuration or real profiles are used.

`run-ssh-tests.ps1` runs additional production-code checks after a Release build.
Pass `-VcVarsPath`, `-Architecture`, and `-ShellPath` (a POSIX shell, including
BusyBox for Windows); add `-PhpPath` for the production PHP client checks.
Python needs Paramiko on its module search path. The runner
links the Release objects and tests a disposable loopback SSH/SFTP peer, file
copy/move, overwrite refusal, read failures, SCP acknowledgements, shell quoting,
and shell upload/delete errors. All files and credentials are synthetic.
Both peers must use the updated plugin for LAN uploads and renames; older peers
refuse the new commands instead of silently replacing files. LAN upload resume
is explicitly unsupported.

The same runner executes `libssh2_boundary_test.c` against the production SFTP and
transport parsers: valid and malformed NAME replies, STATUS request IDs, a short
ETM packet, and malformed EXT_INFO. Guard pages turn out-of-bounds accesses into
deterministic failures. Run both x64 and x86.

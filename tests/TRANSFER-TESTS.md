# Transfer regressions

Run `run-transfer-tests.ps1` with `-VcVarsPath` pointing to the Visual C++ environment script for the target architecture and `-Architecture x64` or `-Architecture x86`. Windows PowerShell 5.1 is supported.

`download_skip_test.cpp` includes the production download error module and uses real Windows file operations. It tests missing files/directories, locked files, move/resume exclusions, nested batches, reset between operations, and independent transfer threads. The Skip all selection is injected into the operation state; the graphical dialog itself is not clicked by this test.

`lan_transfer_test.cpp` includes the production LAN transfer implementation. A loopback TCP peer returns deterministic transfer replies while the production client reads and writes real files. Tests compare the complete file bytes for resumed, fresh, empty, and already-complete downloads, and exercise successful, empty, whitespace-only, and disconnected upload completion replies. An already-connected socket is injected; pairing, discovery, and credential storage are outside the test scope.

`plugin_load_test.cpp` is a separate smoke test for the compiled plugin. Build it with the matching architecture and the `src/include` include directory, then pass the absolute plugin binary path as its only argument. It checks DLL load/unload, initialization, exported functions, 100 batch callback pairs, and the error-dialog resources.

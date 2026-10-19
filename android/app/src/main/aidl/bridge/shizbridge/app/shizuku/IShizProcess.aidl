package bridge.shizbridge.app.shizuku;

import android.os.ParcelFileDescriptor;

/** One process spawned inside the Shizuku UserService (shell uid). */
interface IShizProcess {
    /** Stdout (stderr merged) read end. One-shot: the second call throws. */
    ParcelFileDescriptor acquireStdout() = 2;
    /** Writes to the process stdin. The session chunks large payloads itself. */
    void writeStdin(in byte[] data) = 3;
    /** Closes the process stdin — the peer sees EOF. */
    void closeStdin() = 4;
    /** Blocks until the process exits and returns its exit code. */
    int waitFor() = 5;
    /** Kills the process (SIGKILL after a short grace period). */
    void destroy() = 6;
}

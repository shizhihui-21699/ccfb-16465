// Native decryptor exported as a JNI entry point.
//
// This is the arrangement real packers use: the DEX declares
// `private static native void decrypt(byte[], int, byte[])` and the cipher
// lives here, where DEX-level analysis cannot see it. The routine XORs the
// buffer in place with a 4-byte rolling key — enough to make the point without
// dragging in a crypto library.
//
// Build (aarch64):
//   clang --target=aarch64-linux-gnu -O1 -fno-stack-protector -nostdlib \
//         -fPIC -c decrypt.c -o decrypt.o
//   lld -flavor gnu -shared -o libdecrypt.so decrypt.o
typedef unsigned char u8;

__attribute__((visibility("default")))
void Java_com_example_jnistub_JniLoader_decrypt(u8 *env, void *cls, u8 *buf,
                                                int len, u8 *key) {
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = (u8)(buf[i] ^ key[i & 3]);
    }
}

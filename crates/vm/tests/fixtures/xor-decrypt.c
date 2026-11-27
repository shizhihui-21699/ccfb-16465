// A packer-style decryptor: XOR with a 4-byte key, written the way real stubs are.
void decrypt(unsigned char *buf, int len, const unsigned char *key) {
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = (unsigned char)(buf[i] ^ key[i & 3]);
    }
}

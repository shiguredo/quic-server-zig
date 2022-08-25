const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const openssl = @cImport({
    @cInclude("openssl/evp.h");
});

pub fn decryptAes128Gcm(
    out: []u8,
    cipher: []const u8,
    tag: [Aes128Gcm.tag_length]u8,
    ad: []const u8,
    nonce: [Aes128Gcm.nonce_length]u8,
    key: [Aes128Gcm.key_length]u8,
) !void {
    // Example taken from:
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    //
    // int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
    //                 unsigned char *aad, int aad_len,
    //                 unsigned char *tag,
    //                 unsigned char *key,
    //                 unsigned char *iv, int iv_len,
    //                 unsigned char *plaintext)
    // {
    //     EVP_CIPHER_CTX *ctx;
    //     int len;
    //     int plaintext_len;
    //     int ret;

    //     /* Create and initialise the context */
    //     if(!(ctx = EVP_CIPHER_CTX_new()))
    //         handleErrors();

    //     /* Initialise the decryption operation. */
    //     if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    //         handleErrors();

    //     /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    //     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    //         handleErrors();

    //     /* Initialise key and IV */
    //     if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    //         handleErrors();

    //     /*
    //      * Provide any AAD data. This can be called zero or more times as
    //      * required
    //      */
    //     if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    //         handleErrors();

    //     /*
    //      * Provide the message to be decrypted, and obtain the plaintext output.
    //      * EVP_DecryptUpdate can be called multiple times if necessary
    //      */
    //     if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    //         handleErrors();
    //     plaintext_len = len;

    //     /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    //     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    //         handleErrors();

    //     /*
    //      * Finalise the decryption. A positive return value indicates success,
    //      * anything else is a failure - the plaintext is not trustworthy.
    //      */
    //     ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    //     /* Clean up */
    //     EVP_CIPHER_CTX_free(ctx);

    //     if(ret > 0) {
    //         /* Success */
    //         plaintext_len += len;
    //         return plaintext_len;
    //     } else {
    //         /* Verify failed */
    //         return -1;
    //     }
    // }

    var ctx: ?*openssl.EVP_CIPHER_CTX = null;
    ctx = openssl.EVP_CIPHER_CTX_new();
    if (ctx == null)
        return error.InitializationContextError;

    if (openssl.EVP_DecryptInit_ex(ctx, openssl.EVP_aes_128_gcm(), null, null, null) == 0)
        return error.DecryptInitError;

    if (openssl.EVP_DecryptInit_ex(ctx, null, null, &key, &nonce) == 0)
        return error.KeyAndIVInitializationError;

    var len: c_int = undefined;
    if (openssl.EVP_DecryptUpdate(ctx, null, &len, ad.ptr, @intCast(c_int, ad.len)) == 0)
        return error.DecryptUpdateError;

    var plaintext_len: c_int = undefined;
    if (openssl.EVP_DecryptUpdate(ctx, out.ptr, &plaintext_len, cipher.ptr, @intCast(c_int, cipher.len)) == 0)
        return error.DecryptUpdateError;

    var _tag: [tag.len]u8 = undefined;
    mem.copy(u8, &_tag, &tag);
    if (openssl.EVP_CIPHER_CTX_ctrl(ctx, openssl.EVP_CTRL_GCM_SET_TAG, tag.len, &_tag) == 0)
        return error.SetTagError;

    var final_len: c_int = undefined;
    const ret = openssl.EVP_DecryptFinal_ex(ctx, out.ptr + @intCast(usize, plaintext_len), &final_len);
    openssl.EVP_CIPHER_CTX_free(ctx);

    if (ret == 0)
        return error.DecryptFinalError;
}

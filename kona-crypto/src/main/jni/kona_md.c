/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "kona/kona_common.h"
#include "kona/kona_jni.h"

EVP_MD_CTX* kona_md_create_ctx(const char *algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    const EVP_MD* md = EVP_get_digestbyname(algo);
    if (md == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        OPENSSL_print_err();

        return NULL;
    }

    return ctx;
}

int kona_md_reset(EVP_MD_CTX* ctx) {
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_DigestInit_ex(ctx, NULL, NULL)) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

    return OPENSSL_SUCCESS;
}

int kona_md_free_ctx(EVP_MD_CTX* mdctx) {
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }

    return OPENSSL_SUCCESS;
}

int md_oneshot_digest(const char *algorithm, const unsigned char *input, size_t input_len, unsigned char *output, unsigned int *output_len) {
    EVP_MD_CTX *mdctx = kona_md_create_ctx(algorithm);

    if (!EVP_DigestUpdate(mdctx, input, input_len)) {
        OPENSSL_print_err();

        kona_md_free_ctx(mdctx);
        return OPENSSL_FAILURE;
    }

    if (!EVP_DigestFinal_ex(mdctx, output, output_len)) {
        OPENSSL_print_err();

        EVP_MD_CTX_free(mdctx);
        return OPENSSL_FAILURE;
    }

    kona_md_free_ctx(mdctx);

    return OPENSSL_SUCCESS;
}

int main() {
    const char *input = "message.alt";
    const char *algorithms[] = {"MD5", "SHA-1",
                                "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_len;

    for (int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
        if (md_oneshot_digest(algorithms[i], (unsigned char *) input,
                              strlen(input),
                              output,
                              &output_len)) {
            printf("%s: ", algorithms[i]);
            print_hex(output, 0, output_len);
        } else {
            fprintf(stderr, "Failed to compute md_oneshot_digest for %s\n", algorithms[i]);
        }
    }

    return 0;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdCreateCtx
  (JNIEnv* env, jclass classObj, jstring algorithm) {
    const char* algo = (*env)->GetStringUTFChars(env, algorithm, NULL);
    EVP_MD_CTX* mdctx = kona_md_create_ctx(algo);
    (*env)->ReleaseStringUTFChars(env, algorithm, algo);

    return mdctx == NULL ? OPENSSL_FAILURE : (jlong)mdctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdFreeCtx
  (JNIEnv* env, jclass classObj, jlong pointer) {
    kona_md_free_ctx((EVP_MD_CTX*)pointer);
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdUpdate
  (JNIEnv* env, jclass classObj, jlong pointer, jbyteArray data) {
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)pointer;
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (data == NULL) {
        return OPENSSL_FAILURE;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    if (data_len < 0) {
        return OPENSSL_FAILURE;
    }

    jbyte* data_bytes = (jbyte*)malloc(data_len * sizeof(jbyte));
    if (data_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    (*env)->GetByteArrayRegion(env, data, 0, data_len, data_bytes);

    int result;
    if (EVP_DigestUpdate(ctx, data_bytes, data_len)) {
        result = OPENSSL_SUCCESS;
    } else {
        OPENSSL_print_err();
        result = OPENSSL_FAILURE;
    }

    free(data_bytes);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdFinal
  (JNIEnv* env, jclass classObj, jlong pointer) {
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!kona_md_reset(ctx)) {
        return NULL;
    }

    if (digest_len <= 0) {
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, digest_len);
    if (result == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, digest_len, (jbyte*)digest);

    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdReset
  (JNIEnv* env, jclass classObj, jlong pointer) {
    return kona_md_reset((EVP_MD_CTX*)pointer);
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdClone
  (JNIEnv* env, jclass classObj, jlong pointer) {
    EVP_MD_CTX* orig_ctx = (EVP_MD_CTX*)pointer;
    if (orig_ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_MD_CTX* new_ctx = EVP_MD_CTX_new();
    if (new_ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_MD_CTX_copy_ex(new_ctx, orig_ctx)) {
        OPENSSL_print_err();
        EVP_MD_CTX_free(new_ctx);

        return OPENSSL_FAILURE;
    }

    return (jlong)new_ctx;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_mdOneShotDigest
  (JNIEnv* env, jclass classObj, jstring algorithm, jbyteArray data) {
    const char* algo = (*env)->GetStringUTFChars(env, algorithm, NULL);
    EVP_MD_CTX* ctx = kona_md_create_ctx(algo);
    (*env)->ReleaseStringUTFChars(env, algorithm, algo);
    if (ctx == NULL) {
        return NULL;
    }

    if (data == NULL) {
        kona_md_free_ctx(ctx);

        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    if (data_len < 0) {
        kona_md_free_ctx(ctx);

        return NULL;
    }

    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        kona_md_free_ctx(ctx);

        return NULL;
    }

    if (!EVP_DigestUpdate(ctx, data_bytes, data_len)) {
        (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
        kona_md_free_ctx(ctx);

        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        kona_md_free_ctx(ctx);
        return NULL;
    }

    kona_md_free_ctx(ctx);

    if (digest_len <= 0) {
        return NULL;
    }

    jbyteArray digest_bytes = (*env)->NewByteArray(env, digest_len);
    if (digest_bytes == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, digest_bytes, 0, digest_len, (jbyte*)digest);

    return digest_bytes;
}

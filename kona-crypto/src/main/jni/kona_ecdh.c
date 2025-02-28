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

#include <stdbool.h>
#include <string.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "kona/kona_jni.h"
#include "kona/kona_common.h"
#include "kona/kona_ec.h"

ECDH_CTX* ecdh_create_ctx(int curve_nid, EVP_PKEY* pkey) {
    if (pkey == NULL) {
        return NULL;
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        return NULL;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    ECDH_CTX* ctx = (ECDH_CTX*)OPENSSL_malloc(sizeof(ECDH_CTX));
    if (ctx == NULL) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    ctx->pkey = pkey;
    ctx->pctx = pctx;
    ctx->curve_nid = curve_nid;

    return ctx;
}

ECDH_CTX* ecdh_free_ctx(ECDH_CTX* ctx) {
    if (ctx != NULL) {
        if (ctx->pctx != NULL) {
            EVP_PKEY_CTX_free(ctx->pctx);
            ctx->pctx = NULL;
        }
        if (ctx->pkey != NULL) {
            EVP_PKEY_free(ctx->pkey);
            ctx->pkey = NULL;
        }

        OPENSSL_free(ctx);
    }
}

uint8_t* ecdh_derive(EVP_PKEY_CTX* pkey_ctx, EVP_PKEY* peer_pkey, size_t* shared_key_len) {
    if (!pkey_ctx || !peer_pkey || !shared_key_len) {
        return NULL;
    }

    if (EVP_PKEY_derive_set_peer(pkey_ctx, peer_pkey) <= 0) {
        return NULL;
    }

    if (EVP_PKEY_derive(pkey_ctx, NULL, shared_key_len) <= 0) {
        return NULL;
    }

    uint8_t* shared_key = (uint8_t*)OPENSSL_malloc(*shared_key_len);
    if (!shared_key) {
        return NULL;
    }

    if (EVP_PKEY_derive(pkey_ctx, shared_key, shared_key_len) <= 0) {
        OPENSSL_free(shared_key);
        return NULL;
    }

    return shared_key;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhCreateCtx
  (JNIEnv* env, jclass classObj, jint curveNID, jbyteArray priKey) {
    int key_len = (*env)->GetArrayLength(env, priKey);
    if (key_len <= 0) {
        return OPENSSL_FAILURE;
    }
    jbyte* pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_PKEY* pkey = ec_pri_key(curveNID, (const uint8_t *)pri_key_bytes, key_len);
    (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
    if (pkey == NULL) {
        return OPENSSL_FAILURE;
    }

    ECDH_CTX* ctx = ecdh_create_ctx(curveNID, pkey);
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);

        return OPENSSL_FAILURE;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhFreeCtx
  (JNIEnv* env, jclass classObj, jlong pointer) {
    ecdh_free_ctx((ECDH_CTX*)pointer);
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhDeriveKey
  (JNIEnv* env, jclass classObj, jlong pointer, jbyteArray peerPubKey) {
    ECDH_CTX* ctx = (ECDH_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jsize peer_pub_key_len = (*env)->GetArrayLength(env, peerPubKey);
    if (peer_pub_key_len <= 0) {
        return NULL;
    }
    jbyte* peer_pub_key_bytes = (*env)->GetByteArrayElements(env, peerPubKey, NULL);
    if (peer_pub_key_bytes == NULL) {
        return NULL;
    }

    EVP_PKEY* peer_pkey = ec_pub_key(ctx->curve_nid, (const uint8_t*)peer_pub_key_bytes, peer_pub_key_len);
    (*env)->ReleaseByteArrayElements(env, peerPubKey, peer_pub_key_bytes, JNI_ABORT);
    if (peer_pkey == NULL) {
        return NULL;
    }

    size_t shared_key_len;
    uint8_t* shared_key = ecdh_derive(ctx->pctx, peer_pkey, &shared_key_len);
    EVP_PKEY_free(peer_pkey);
    if (shared_key == NULL) {
        return NULL;
    }

    jbyteArray shared_key_bytes = (*env)->NewByteArray(env, shared_key_len);
    if (shared_key_bytes != NULL) {
        (*env)->SetByteArrayRegion(env, shared_key_bytes, 0, shared_key_len, (jbyte*)shared_key);
    }

    OPENSSL_free(shared_key);

    return shared_key_bytes;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhOneShotDeriveKey
  (JNIEnv* env, jclass classObj, jint curveNID, jbyteArray priKey, jbyteArray peerPubKey) {
    int key_len = (*env)->GetArrayLength(env, priKey);
    if (key_len <= 0) {
        return NULL;
    }
    jbyte* pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        return NULL;
    }

    EVP_PKEY* pkey = ec_pri_key(curveNID, (const uint8_t *)pri_key_bytes, key_len);
    (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
    if (pkey == NULL) {
        return NULL;
    }

    ECDH_CTX* ctx = ecdh_create_ctx(curveNID, pkey);
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);

        return NULL;
    }

    jsize peer_pub_key_len = (*env)->GetArrayLength(env, peerPubKey);
    if (peer_pub_key_len <= 0) {
        ecdh_free_ctx(ctx);
        return NULL;
    }
    jbyte* peer_pub_key_bytes = (*env)->GetByteArrayElements(env, peerPubKey, NULL);
    if (peer_pub_key_bytes == NULL) {
        ecdh_free_ctx(ctx);

        return NULL;
    }

    EVP_PKEY* peer_pkey = ec_pub_key(ctx->curve_nid, (const uint8_t*)peer_pub_key_bytes, peer_pub_key_len);
    (*env)->ReleaseByteArrayElements(env, peerPubKey, peer_pub_key_bytes, JNI_ABORT);
    if (peer_pkey == NULL) {
        ecdh_free_ctx(ctx);

        return NULL;
    }

    size_t shared_key_len;
    uint8_t* shared_key = ecdh_derive(ctx->pctx, peer_pkey, &shared_key_len);
    EVP_PKEY_free(peer_pkey);
    if (shared_key == NULL) {
        ecdh_free_ctx(ctx);

        return NULL;
    }

    jbyteArray shared_key_bytes = (*env)->NewByteArray(env, shared_key_len);
    if (shared_key_bytes != NULL) {
        (*env)->SetByteArrayRegion(env, shared_key_bytes, 0, shared_key_len, (jbyte*)shared_key);
    }

    OPENSSL_free(shared_key);
    ecdh_free_ctx(ctx);

    return shared_key_bytes;
}

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

package com.tencent.kona.crypto.provider.nativeImpl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.nio.charset.StandardCharsets;

import static com.tencent.kona.crypto.CryptoUtils.copy;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for the native message digest implementations.
 */
@EnabledOnOs({OS.LINUX, OS.MAC})
public class NativeMessageDigestTest {

    private static final byte[] MESSAGE_0 = new byte[0];
    private static final byte[] MESSAGE = "message".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MESSAGE_ALT = "message.alt".getBytes(StandardCharsets.UTF_8);

    private static final byte[] DIGEST_MD5 = toBytes("78e731027d8fd50ed642340b7c9a63b3");
    private static final byte[] DIGEST_SHA1 = toBytes("6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d");

    private static final byte[] DIGEST_SHA224 = toBytes("ff51ddfabb180148583ba6ac23483acd2d049e7c4fdba6a891419320");
    private static final byte[] DIGEST_SHA256 = toBytes("ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
    private static final byte[] DIGEST_SHA256_ALT = toBytes("e11a06340a935eb5ebe060c479b9f2d00f4a28513357bfef68e2acb00d5fe964");
    private static final byte[] DIGEST_SHA384 = toBytes("353eb7516a27ef92e96d1a319712d84b902eaa828819e53a8b09af7028103a9978ba8feb6161e33c3619c5da4c4666a5");
    private static final byte[] DIGEST_SHA512 = toBytes("f8daf57a3347cc4d6b9d575b31fe6077e2cb487f60a96233c08cb479dbf31538cc915ec6d48bdbaa96ddc1a16db4f4f96f37276cfcb3510b8246241770d5952c");

    private static final byte[] DIGEST_SHA3_224 = toBytes("29b8cdd610daa7f31a05f8855c403ec4e11133903600d3685f25b5bd");
    private static final byte[] DIGEST_SHA3_256 = toBytes("7f4a23d90de90d100754f82d6c14073b7fb466f76fd1f61b187b9f39c3ffd895");
    private static final byte[] DIGEST_SHA3_384 = toBytes("cff0a8cb36aa0dea0c14a6396359508979b24ed4aa9ff1fda428d26ea8f7309612f6c4e441042a20b5fde32e11e1d9b9");
    private static final byte[] DIGEST_SHA3_512 = toBytes("6b68516bdfd85cb5b6cdfa7ce6994ae8e59053997bcad939dd79f254dea783e7b93a82d4b4a7299029c62e009f9f130dfd42825527984159c783447a9ec142cb");

    @Test
    public void testKAT() {
        checkDigest("MD5", DIGEST_MD5);
        checkDigest("SHA-1", DIGEST_SHA1);

        checkDigest("SHA-224", DIGEST_SHA224);
        checkDigest("SHA-256", DIGEST_SHA256);
        checkDigest("SHA-384", DIGEST_SHA384);
        checkDigest("SHA-512", DIGEST_SHA512);

        checkDigest("SHA3-224", DIGEST_SHA3_224);
        checkDigest("SHA3-256", DIGEST_SHA3_256);
        checkDigest("SHA3-384", DIGEST_SHA3_384);
        checkDigest("SHA3-512", DIGEST_SHA3_512);
    }

    private static void checkDigest(String algorithm, byte[] expectedDigest) {
        try(NativeMessageDigest md = new NativeMessageDigest(algorithm)) {
            md.update(MESSAGE);
            byte[] digest = md.doFinal();
            Assertions.assertArrayEquals(expectedDigest, digest);
        }
    }

    @Test
    public void testOneShotKAT() {
        checkOneShotDigest("MD5", DIGEST_MD5);
        checkOneShotDigest("SHA-1", DIGEST_SHA1);

        checkOneShotDigest("SHA-224", DIGEST_SHA224);
        checkOneShotDigest("SHA-256", DIGEST_SHA256);
        checkOneShotDigest("SHA-384", DIGEST_SHA384);
        checkOneShotDigest("SHA-512", DIGEST_SHA512);

        checkOneShotDigest("SHA3-224", DIGEST_SHA3_224);
        checkOneShotDigest("SHA3-256", DIGEST_SHA3_256);
        checkOneShotDigest("SHA3-384", DIGEST_SHA3_384);
        checkOneShotDigest("SHA3-512", DIGEST_SHA3_512);
    }

    private static void checkOneShotDigest(String algorithm, byte[] expectedDigest) {
        byte[] digest = NativeCrypto.mdOneShotDigest(algorithm, MESSAGE);
        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testUpdate() {
        try(NativeMessageDigest md = new NativeMessageDigest("SHA-256")) {

            md.update(copy(MESSAGE, 0, MESSAGE.length / 3));
            md.update(copy(MESSAGE, MESSAGE.length / 3, MESSAGE.length - MESSAGE.length / 3));
            byte[] digest = md.doFinal();

            Assertions.assertArrayEquals(DIGEST_SHA256, digest);
        }
    }

    @Test
    public void testReuse() {
        try(NativeMessageDigest md = new NativeMessageDigest("SHA-256")) {
            byte[] digest1 = md.doFinal(MESSAGE);
            Assertions.assertArrayEquals(DIGEST_SHA256, digest1);

            byte[] digest2 = md.doFinal(MESSAGE_ALT);
            Assertions.assertArrayEquals(DIGEST_SHA256_ALT, digest2);
        }
    }

    @Test
    public void testReset() {
        try(NativeMessageDigest md = new NativeMessageDigest("SHA-256")) {

            md.update(MESSAGE);
            md.reset();
            md.update(MESSAGE_ALT);
            byte[] digest = md.doFinal();

            Assertions.assertArrayEquals(DIGEST_SHA256_ALT, digest);
        }
    }

    @Test
    public void testClone() {
        try(NativeMessageDigest md = new NativeMessageDigest("SHA-256")) {
            md.update(MESSAGE);

            try (NativeMessageDigest clone = md.clone()) {
                byte[] digest = clone.doFinal();

                Assertions.assertArrayEquals(DIGEST_SHA256, digest);
            }
        }
    }

    @Test
    public void testEmptyData() {
        try(NativeMessageDigest md = new NativeMessageDigest("SHA-256")) {
            byte[] digest = md.doFinal(MESSAGE_0);
            Assertions.assertEquals(32, digest.length);
        }
    }

    @Test
    public void testNullData() {
        try(NativeMessageDigest md = new NativeMessageDigest("SHA-256")) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> md.doFinal(null));
        }
    }

    @Test
    public void testUseClosedRef() {
        NativeMessageDigest md = new NativeMessageDigest("SHA-256");
        md.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> md.doFinal(MESSAGE));
    }

    @Test
    public void testCloseTwice() {
        NativeMessageDigest md = new NativeMessageDigest("SHA-256");
        md.doFinal(MESSAGE);
        md.close();
        md.close();
    }
}

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

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.util.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Random;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for the message digests.
 */
public class KonaMessageDigestTest {

    private static final byte[] MESSAGE = "message".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MESSAGE_ALT = "message.alt".getBytes(StandardCharsets.UTF_8);

    private static final byte[] DIGEST_MD5 = toBytes("78e731027d8fd50ed642340b7c9a63b3");
    private static final byte[] DIGEST_MD5_ALT = toBytes("614ab8bacdcada35644c3cff9a5c7459");

    private static final byte[] DIGEST_SHA1 = toBytes("6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d");
    private static final byte[] DIGEST_SHA1_ALT = toBytes("b154bd47ae95a4e7ac3e51245363537e13309e6c");

    private static final byte[] DIGEST_SHA224 = toBytes("ff51ddfabb180148583ba6ac23483acd2d049e7c4fdba6a891419320");
    private static final byte[] DIGEST_SHA224_ALT = toBytes("ae9de426e3f94133b92d26f759209f45a1baa6d6ccebe8ab50cd37cd");
    private static final byte[] DIGEST_SHA256 = toBytes("ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
    private static final byte[] DIGEST_SHA256_ALT = toBytes("e11a06340a935eb5ebe060c479b9f2d00f4a28513357bfef68e2acb00d5fe964");
    private static final byte[] DIGEST_SHA384 = toBytes("353eb7516a27ef92e96d1a319712d84b902eaa828819e53a8b09af7028103a9978ba8feb6161e33c3619c5da4c4666a5");
    private static final byte[] DIGEST_SHA384_ALT = toBytes("52b73939cfabd6a666aaa915037cc0a7e4d71512aa0ed5307f5907fbb0be90acaab79d3a52095834823cf97516112229");
    private static final byte[] DIGEST_SHA512 = toBytes("f8daf57a3347cc4d6b9d575b31fe6077e2cb487f60a96233c08cb479dbf31538cc915ec6d48bdbaa96ddc1a16db4f4f96f37276cfcb3510b8246241770d5952c");
    private static final byte[] DIGEST_SHA512_ALT = toBytes("06cffd135f00f3fbd09662bd46d2451396174a9029ff488928e1b4ad71b85ec789fe683c637305bf333b92247b026b7f84e496c0ce5200f7b0631de9a30d508b");

    private static final byte[] DIGEST_SHA3_224 = toBytes("29b8cdd610daa7f31a05f8855c403ec4e11133903600d3685f25b5bd");
    private static final byte[] DIGEST_SHA3_224_ALT = toBytes("f0948e01a4cfce7839580cf1e7b10b16e95fe87554459b2f821fe2d8");
    private static final byte[] DIGEST_SHA3_256 = toBytes("7f4a23d90de90d100754f82d6c14073b7fb466f76fd1f61b187b9f39c3ffd895");
    private static final byte[] DIGEST_SHA3_256_ALT = toBytes("b78a306afb1cdc954328dd5023ac11b81fb1308232b14a710901e5f4188a8074");
    private static final byte[] DIGEST_SHA3_384 = toBytes("cff0a8cb36aa0dea0c14a6396359508979b24ed4aa9ff1fda428d26ea8f7309612f6c4e441042a20b5fde32e11e1d9b9");
    private static final byte[] DIGEST_SHA3_384_ALT = toBytes("1c6235aebb151acb853f36a61f931b17f55760a6c31ccf1e29953189377a888c8c394c76729c412ada3fc8151bb75142");
    private static final byte[] DIGEST_SHA3_512 = toBytes("6b68516bdfd85cb5b6cdfa7ce6994ae8e59053997bcad939dd79f254dea783e7b93a82d4b4a7299029c62e009f9f130dfd42825527984159c783447a9ec142cb");
    private static final byte[] DIGEST_SHA3_512_ALT = toBytes("782ab051049ddda56cef9fcc622bd9ed881587116c8e4eb498f3dd242b3089b6c751f817d60ac57677f482bb217b0708920f9faff5dab6187ab101af4035f833");


    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKAT() throws Exception {
        checkDigest("MD5", MESSAGE, DIGEST_MD5);
        checkDigest("SHA-1", MESSAGE, DIGEST_SHA1);

        checkDigest("SHA-224", MESSAGE, DIGEST_SHA224);
        checkDigest("SHA-256", MESSAGE, DIGEST_SHA256);
        checkDigest("SHA-384", MESSAGE, DIGEST_SHA384);
        checkDigest("SHA-512", MESSAGE, DIGEST_SHA512);

        checkDigest("SHA3-224", MESSAGE, DIGEST_SHA3_224);
        checkDigest("SHA3-256", MESSAGE, DIGEST_SHA3_256);
        checkDigest("SHA3-384", MESSAGE, DIGEST_SHA3_384);
        checkDigest("SHA3-512", MESSAGE, DIGEST_SHA3_512);
    }

    @Test
    public void testAlias() throws Exception {
        checkDigest("SHA1", MESSAGE, DIGEST_SHA1);

        checkDigest("SHA224", MESSAGE, DIGEST_SHA224);
        checkDigest("SHA256", MESSAGE, DIGEST_SHA256);
        checkDigest("SHA384", MESSAGE, DIGEST_SHA384);
        checkDigest("SHA512", MESSAGE, DIGEST_SHA512);
    }

    private static void checkDigest(String name, byte[] message,
            byte[] expectedDigest) throws Exception {
        MessageDigest md = MessageDigest.getInstance(name, PROVIDER);
        byte[] digest = md.digest(message);
        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testGetDigestLength() throws Exception {
        checkGetDigestLength("MD5", 16);
        checkGetDigestLength("SHA-1", 20);

        checkGetDigestLength("SHA-224", 28);
        checkGetDigestLength("SHA-256", 32);
        checkGetDigestLength("SHA-384", 48);
        checkGetDigestLength("SHA-512", 64);

        checkGetDigestLength("SHA3-224", 28);
        checkGetDigestLength("SHA3-256", 32);
        checkGetDigestLength("SHA3-384", 48);
        checkGetDigestLength("SHA3-512", 64);
    }

    void checkGetDigestLength(String algorithm, int expectedDigestLength)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        int digestLength = md.getDigestLength();
        Assertions.assertEquals(expectedDigestLength, digestLength);
    }

    @Test
    public void testUpdateByte() throws Exception {
        checkUpdateByte("MD5", DIGEST_MD5);
        checkUpdateByte("SHA-1", DIGEST_SHA1);

        checkUpdateByte("SHA-224", DIGEST_SHA224);
        checkUpdateByte("SHA-256", DIGEST_SHA256);
        checkUpdateByte("SHA-384", DIGEST_SHA384);
        checkUpdateByte("SHA-512", DIGEST_SHA512);

        checkUpdateByte("SHA3-224", DIGEST_SHA3_224);
        checkUpdateByte("SHA3-256", DIGEST_SHA3_256);
        checkUpdateByte("SHA3-384", DIGEST_SHA3_384);
        checkUpdateByte("SHA3-512", DIGEST_SHA3_512);
    }

    private void checkUpdateByte(String algorithm, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

        for (byte b : MESSAGE) {
            md.update(b);
        }
        byte[] digest= md.digest();

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testUpdateBytes() throws Exception {
        checkUpdateBytes("MD5", DIGEST_MD5);
        checkUpdateBytes("SHA-1", DIGEST_SHA1);

        checkUpdateBytes("SHA-224", DIGEST_SHA224);
        checkUpdateBytes("SHA-256", DIGEST_SHA256);
        checkUpdateBytes("SHA-384", DIGEST_SHA384);
        checkUpdateBytes("SHA-512", DIGEST_SHA512);

        checkUpdateBytes("SHA3-224", DIGEST_SHA3_224);
        checkUpdateBytes("SHA3-256", DIGEST_SHA3_256);
        checkUpdateBytes("SHA3-384", DIGEST_SHA3_384);
        checkUpdateBytes("SHA3-512", DIGEST_SHA3_512);
    }

    private void checkUpdateBytes(String algorithm, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

        md.update(MESSAGE, 0, MESSAGE.length / 2);
        md.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        byte[] digest = md.digest();

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testOutputBuf() throws Exception {
        checkOutputBuf("MD5", DIGEST_MD5);
        checkOutputBuf("SHA-1", DIGEST_SHA1);

        checkOutputBuf("SHA-224", DIGEST_SHA224);
        checkOutputBuf("SHA-256", DIGEST_SHA256);
        checkOutputBuf("SHA-384", DIGEST_SHA384);
        checkOutputBuf("SHA-512", DIGEST_SHA512);

        checkOutputBuf("SHA3-224", DIGEST_SHA3_224);
        checkOutputBuf("SHA3-256", DIGEST_SHA3_256);
        checkOutputBuf("SHA3-384", DIGEST_SHA3_384);
        checkOutputBuf("SHA3-512", DIGEST_SHA3_512);
    }

    private void checkOutputBuf(String algorithm, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        md.update(MESSAGE);
        byte[] out = new byte[expectedDigest.length];
        int length = md.digest(out, 0, out.length);

        Assertions.assertEquals(expectedDigest.length, length);
        Assertions.assertArrayEquals(expectedDigest, out);
    }

    @Test
    public void testNullBytes() throws Exception {
        checkNullBytes("MD5");
        checkNullBytes("SHA-1");

        checkNullBytes("SHA-224");
        checkNullBytes("SHA-256");
        checkNullBytes("SHA-384");
        checkNullBytes("SHA-512");

        checkNullBytes("SHA3-224");
        checkNullBytes("SHA3-256");
        checkNullBytes("SHA3-384");
        checkNullBytes("SHA3-512");
    }

    private void checkNullBytes(String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        Assertions.assertThrows(
                NullPointerException.class,
                () -> md.update((byte[]) null));
    }

    @Test
    public void testByteBuffer() throws Exception {
        checkByteBuffer("MD5", DIGEST_MD5);
        checkByteBuffer("SHA-1", DIGEST_SHA1);

        checkByteBuffer("SHA-224", DIGEST_SHA224);
        checkByteBuffer("SHA-256", DIGEST_SHA256);
        checkByteBuffer("SHA-384", DIGEST_SHA384);
        checkByteBuffer("SHA-512", DIGEST_SHA512);

        checkByteBuffer("SHA3-224", DIGEST_SHA3_224);
        checkByteBuffer("SHA3-256", DIGEST_SHA3_256);
        checkByteBuffer("SHA3-384", DIGEST_SHA3_384);
        checkByteBuffer("SHA3-512", DIGEST_SHA3_512);
    }

    private void checkByteBuffer(String algorithm, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        md.update(ByteBuffer.wrap(MESSAGE));
        byte[] digest = md.digest();
        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testNullByteBuffer() throws Exception {
        checkNullByteBuffer("MD5");
        checkNullByteBuffer("SHA-1");

        checkNullByteBuffer("SHA-224");
        checkNullByteBuffer("SHA-256");
        checkNullByteBuffer("SHA-384");
        checkNullByteBuffer("SHA-512");

        checkNullByteBuffer("SHA3-224");
        checkNullByteBuffer("SHA3-256");
        checkNullByteBuffer("SHA3-384");
        checkNullByteBuffer("SHA3-512");
    }

    private void checkNullByteBuffer(String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        Assertions.assertThrows(
                NullPointerException.class,
                () -> md.update((ByteBuffer) null));
    }

    @Test
    public void testEmptyInput() throws Exception {
        checkEmptyInput("MD5");
        checkEmptyInput("SHA-1");

        checkEmptyInput("SHA-224");
        checkEmptyInput("SHA-256");
        checkEmptyInput("SHA-384");
        checkEmptyInput("SHA-512");

        checkEmptyInput("SHA3-224");
        checkEmptyInput("SHA3-256");
        checkEmptyInput("SHA3-384");
        checkEmptyInput("SHA3-512");
    }

    private void checkEmptyInput(String algorithm) throws Exception {
        MessageDigest md1 = MessageDigest.getInstance(algorithm, PROVIDER);
        md1.update(new byte[0]);
        byte[] digest1 = md1.digest();

        MessageDigest md2 = MessageDigest.getInstance(algorithm, PROVIDER);
        md2.update(ByteBuffer.wrap(new byte[0]));
        byte[] digest2 = md2.digest();

        Assertions.assertArrayEquals(digest1, digest2);
    }

    @Test
    public void testNoInput() throws Exception {
        checkNoInput("MD5");
        checkNoInput("SHA-1");

        checkNoInput("SHA-224");
        checkNoInput("SHA-256");
        checkNoInput("SHA-384");
        checkNoInput("SHA-512");

        checkNoInput("SHA3-224");
        checkNoInput("SHA3-256");
        checkNoInput("SHA3-384");
        checkNoInput("SHA3-512");
    }

    private void checkNoInput(String algorithm) throws Exception {
        MessageDigest md1 = MessageDigest.getInstance(algorithm, PROVIDER);
        byte[] digest1 = md1.digest();

        MessageDigest md2 = MessageDigest.getInstance(algorithm, PROVIDER);
        md2.update(new byte[0]);
        byte[] digest2 = md2.digest();

        Assertions.assertArrayEquals(digest1, digest2);
    }

    @Test
    public void testBigData() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        byte[] digest = md.digest(TestUtils.dataMB(10));
        Assertions.assertEquals(Constants.SM3_DIGEST_LEN, digest.length);
    }

    @Test
    public void testBigByteBuffer() throws Exception {
        byte[] data = TestUtils.dataMB(10);

        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        byte[] digest = md.digest(data);

        MessageDigest mdBuffer = MessageDigest.getInstance("SM3", PROVIDER);
        mdBuffer.update(ByteBuffer.wrap(data));
        byte[] digestBuffer = mdBuffer.digest();

        Assertions.assertArrayEquals(digest, digestBuffer);
    }

    @Test
    public void testReuse() throws Exception {
        checkReuse("MD5", DIGEST_MD5, DIGEST_MD5_ALT);
        checkReuse("SHA-1", DIGEST_SHA1, DIGEST_SHA1_ALT);

        checkReuse("SHA-224", DIGEST_SHA224, DIGEST_SHA224_ALT);
        checkReuse("SHA-256", DIGEST_SHA256, DIGEST_SHA256_ALT);
        checkReuse("SHA-384", DIGEST_SHA384, DIGEST_SHA384_ALT);
        checkReuse("SHA-512", DIGEST_SHA512, DIGEST_SHA512_ALT);

        checkReuse("SHA3-224", DIGEST_SHA3_224, DIGEST_SHA3_224_ALT);
        checkReuse("SHA3-256", DIGEST_SHA3_256, DIGEST_SHA3_256_ALT);
        checkReuse("SHA3-384", DIGEST_SHA3_384, DIGEST_SHA3_384_ALT);
        checkReuse("SHA3-512", DIGEST_SHA3_512, DIGEST_SHA3_512_ALT);
    }

    private void checkReuse(String algorithm,
            byte[] expectedDigest, byte[] expectedDigestAlt) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

        byte[] digestShort = md.digest(MESSAGE);
        Assertions.assertArrayEquals(expectedDigest, digestShort);

        byte[] digestLong = md.digest(MESSAGE_ALT);
        Assertions.assertArrayEquals(expectedDigestAlt, digestLong);
    }

    @Test
    public void testReset() throws Exception {
        checkReset("MD5", DIGEST_MD5);
        checkReset("SHA-1", DIGEST_SHA1);

        checkReset("SHA-224", DIGEST_SHA224);
        checkReset("SHA-256", DIGEST_SHA256);
        checkReset("SHA-384", DIGEST_SHA384);
        checkReset("SHA-512", DIGEST_SHA512);

        checkReset("SHA3-224", DIGEST_SHA3_224);
        checkReset("SHA3-256", DIGEST_SHA3_256);
        checkReset("SHA3-384", DIGEST_SHA3_384);
        checkReset("SHA3-512", DIGEST_SHA3_512);
    }

    public void checkReset(String algorithm, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

        md.update(MESSAGE, 0, MESSAGE.length / 2);
        md.reset();
        md.update(MESSAGE, 0, MESSAGE.length / 2);
        md.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        byte[] digest = md.digest();

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testKATParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testKAT();
            return null;
        });
    }

    @Test
    public void testKATSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testKAT();
            return null;
        });
    }

    @Test
    public void testOutOfBoundsOnUpdate() throws Exception {
        checkOutOfBoundsOnUpdate("MD5");
        checkOutOfBoundsOnUpdate("SHA-1");

        checkOutOfBoundsOnUpdate("SHA-224");
        checkOutOfBoundsOnUpdate("SHA-256");
        checkOutOfBoundsOnUpdate("SHA-384");

        checkOutOfBoundsOnUpdate("SHA-512");
        checkOutOfBoundsOnUpdate("SHA3-224");
        checkOutOfBoundsOnUpdate("SHA3-256");
        checkOutOfBoundsOnUpdate("SHA3-384");
        checkOutOfBoundsOnUpdate("SHA3-512");
    }

    private void checkOutOfBoundsOnUpdate(String algorithm) throws Exception {
        outOfBoundsOnUpdate(algorithm, 7, 0, 32);
        outOfBoundsOnUpdate(algorithm, 16, -8, 16);
        outOfBoundsOnUpdate(algorithm, 16, 8, -8);
        outOfBoundsOnUpdate(algorithm, 16, Integer.MAX_VALUE, 8);
    }

    private static void outOfBoundsOnUpdate(String algorithm,
            int inputSize, int ofs, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

        try {
            md.update(new byte[inputSize], ofs, len);
            throw new Exception("invalid call succeeded");
        } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException e) {
            System.out.println("Expected: " + e);
        }
    }

    @Test
    public void testOutOfBoundsOnOutBuf() throws Exception {
        checkOutOfBoundsOnOutBuf("MD5", 16);
        checkOutOfBoundsOnOutBuf("SHA-1", 20);

        checkOutOfBoundsOnOutBuf("SHA-224", 28);
        checkOutOfBoundsOnOutBuf("SHA-256", 32);
        checkOutOfBoundsOnOutBuf("SHA-384", 48);
        checkOutOfBoundsOnOutBuf("SHA-512", 64);

        checkOutOfBoundsOnOutBuf("SHA3-224", 28);
        checkOutOfBoundsOnOutBuf("SHA3-256", 32);
        checkOutOfBoundsOnOutBuf("SHA3-384", 48);
        checkOutOfBoundsOnOutBuf("SHA3-512", 64);
    }

    private void checkOutOfBoundsOnOutBuf(String algorithm, int digestLength)
            throws Exception {
        outOfBoundsOnOutBuf(algorithm, digestLength, 0, digestLength + 1);
        outOfBoundsOnOutBuf(algorithm, digestLength, 0, digestLength - 1);
        outOfBoundsOnOutBuf(algorithm, digestLength, -1, digestLength);
        outOfBoundsOnOutBuf(algorithm, digestLength, Integer.MAX_VALUE, 32);
    }

    private static void outOfBoundsOnOutBuf(String algorithm,
            int outSize, int ofs, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        md.update(MESSAGE);

        try {
            md.digest(new byte[outSize], ofs, len);
            throw new Exception("invalid call succeeded");
        } catch (IllegalArgumentException | DigestException
                 | ArrayIndexOutOfBoundsException e) {
            System.out.println("Expected: " + e);
        }
    }

    @Test
    public void testOffset() throws Exception {
        testOffset("MD5");
        testOffset("SHA-1");

        testOffset("SHA-224");
        testOffset("SHA-256");
        testOffset("SHA-384");
        testOffset("SHA-512");

        testOffset("SHA3-224");
        testOffset("SHA3-256");
        testOffset("SHA3-384");
        testOffset("SHA3-512");
    }

    private void testOffset(String algorithm) throws Exception {
        offset(algorithm, 0, 64, 0, 128);
        offset(algorithm, 0, 64, 0, 129);
        offset(algorithm, 1, 32, 1, 129);
    }

    private static void offset(String algorithm,
            int minOffset, int maxOffset, int minLen, int maxLen)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);

        Random random = new Random();
        for (int len = minLen; len <= maxLen; len++) {
            byte[] data = new byte[len];
            random.nextBytes(data);
            byte[] digest = null;
            for (int offset = minOffset; offset <= maxOffset; offset++) {
                byte[] offsetData = new byte[len + maxOffset];
                random.nextBytes(offsetData);
                System.arraycopy(data, 0, offsetData, offset, len);
                md.update(offsetData, offset, len);
                byte[] offsetDigest = md.digest();
                if (digest == null) {
                    digest = offsetDigest;
                } else {
                    Assertions.assertArrayEquals(digest, offsetDigest);
                }
            }
        }
    }

    @Test
    public void testClone() throws Exception {
        testClone("MD5", DIGEST_MD5);
        testClone("SHA-1", DIGEST_SHA1);

        testClone("SHA-224", DIGEST_SHA224);
        testClone("SHA-256", DIGEST_SHA256);
        testClone("SHA-384", DIGEST_SHA384);
        testClone("SHA-512", DIGEST_SHA512);

        testClone("SHA3-224", DIGEST_SHA3_224);
        testClone("SHA3-256", DIGEST_SHA3_256);
        testClone("SHA3-384", DIGEST_SHA3_384);
        testClone("SHA3-512", DIGEST_SHA3_512);
    }

    private void testClone(String algorithm, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
        md.update(MESSAGE, 0, MESSAGE.length / 3);
        md.update(MESSAGE[MESSAGE.length / 3]);

        MessageDigest clone = (MessageDigest) md.clone();
        clone.update(MESSAGE, MESSAGE.length / 3 + 1,
                MESSAGE.length - MESSAGE.length / 3 - 2);
        clone.update(MESSAGE[MESSAGE.length - 1]);
        byte[] digest = clone.digest();

        Assertions.assertArrayEquals(expectedDigest, digest);
    }
}

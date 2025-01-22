/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.crypto.provider.nativeImpl;

import com.tencent.kona.jdk.internal.util.Preconditions;

import java.security.MessageDigest;

public class KonaOneShotMessageDigest extends MessageDigest implements Cloneable {

    private final ByteArrayWriter buffer = new ByteArrayWriter();

    private final int digestLength;

    public KonaOneShotMessageDigest(String algorithm, int digestLength) {
        super(algorithm);
        this.digestLength = digestLength;
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(new byte[] { input });
    }

    @Override
    protected int engineGetDigestLength() {
        return digestLength;
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (len == 0) {
            return;
        }
        Preconditions.checkFromIndexSize(
                offset, len, input.length, Preconditions.AIOOBE_FORMATTER);

        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] digest = NativeCrypto.mdOneShotDigest(
                getAlgorithm(), buffer.toByteArray());
        buffer.reset();
        return digest;
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    @Override
    public KonaOneShotMessageDigest clone() throws CloneNotSupportedException {
        KonaOneShotMessageDigest clone = new KonaOneShotMessageDigest(
                getAlgorithm(), getDigestLength());
        clone.buffer.write(buffer.toByteArray());
        return clone;
    }

    public static class MD5 extends KonaOneShotMessageDigest {

        public MD5() {
            super("MD5", 16);
        }
    }

    public static class SHA1 extends KonaOneShotMessageDigest {

        public SHA1() {
            super("SHA-1", 20);
        }
    }

    public static class SHA224 extends KonaOneShotMessageDigest {

        public SHA224() {
            super("SHA-224", 28);
        }
    }

    public static class SHA256 extends KonaOneShotMessageDigest {

        public SHA256() {
            super("SHA-256", 32);
        }
    }

    public static class SHA384 extends KonaOneShotMessageDigest {

        public SHA384() {
            super("SHA-384", 48);
        }
    }

    public static class SHA512 extends KonaOneShotMessageDigest {

        public SHA512() {
            super("SHA-512", 64);
        }
    }

    public static class SHA3_224 extends KonaOneShotMessageDigest {

        public SHA3_224() {
            super("SHA3-224", 28);
        }
    }

    public static class SHA3_256 extends KonaOneShotMessageDigest {

        public SHA3_256() {
            super("SHA3-256", 32);
        }
    }

    public static class SHA3_384 extends KonaOneShotMessageDigest {

        public SHA3_384() {
            super("SHA3-384", 48);
        }
    }

    public static class SHA3_512 extends KonaOneShotMessageDigest {

        public SHA3_512() {
            super("SHA3-512", 64);
        }
    }
}

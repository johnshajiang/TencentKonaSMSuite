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

import com.tencent.kona.crypto.util.Sweeper;
import com.tencent.kona.jdk.internal.util.Preconditions;

import java.security.MessageDigest;

public class KonaMessageDigest extends MessageDigest implements Cloneable {

    private static final Sweeper SWEEPER = Sweeper.instance();

    private final int digestLength;

    private NativeMessageDigest md;

    public KonaMessageDigest(String algorithm, int digestLength) {
        super(algorithm);
        this.digestLength = digestLength;

        md = new NativeMessageDigest(algorithm);

        SWEEPER.register(this, new SweepNativeRef(md));
    }

    @Override
    protected void engineUpdate(byte input) {
        md.update(new byte[] { input });
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

        byte[] data = new byte[len];
        System.arraycopy(input, offset, data, 0, len);
        md.update(data);
    }

    @Override
    protected byte[] engineDigest() {
        return md.doFinal();
    }

    @Override
    protected void engineReset() {
        md.reset();
    }

    @Override
    public KonaMessageDigest clone() throws CloneNotSupportedException {
        KonaMessageDigest clone = (KonaMessageDigest) super.clone();
        clone.md = md.clone();
        return clone;
    }

    public static class MD5 extends KonaMessageDigest {

        public MD5() {
            super("MD5", 16);
        }
    }

    public static class SHA1 extends KonaMessageDigest {

        public SHA1() {
            super("SHA-1", 20);
        }
    }

    public static class SHA224 extends KonaMessageDigest {

        public SHA224() {
            super("SHA-224", 28);
        }
    }

    public static class SHA256 extends KonaMessageDigest {

        public SHA256() {
            super("SHA-256", 32);
        }
    }

    public static class SHA384 extends KonaMessageDigest {

        public SHA384() {
            super("SHA-384", 48);
        }
    }

    public static class SHA512 extends KonaMessageDigest {

        public SHA512() {
            super("SHA-512", 64);
        }
    }

    public static class SHA3_224 extends KonaMessageDigest {

        public SHA3_224() {
            super("SHA3-224", 28);
        }
    }

    public static class SHA3_256 extends KonaMessageDigest {

        public SHA3_256() {
            super("SHA3-256", 32);
        }
    }

    public static class SHA3_384 extends KonaMessageDigest {

        public SHA3_384() {
            super("SHA3-384", 48);
        }
    }

    public static class SHA3_512 extends KonaMessageDigest {

        public SHA3_512() {
            super("SHA3-512", 64);
        }
    }
}

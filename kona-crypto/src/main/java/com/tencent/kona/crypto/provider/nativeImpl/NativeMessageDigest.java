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

import java.util.Objects;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.OPENSSL_SUCCESS;

/**
 * The native message digest implementation.
 */
final class NativeMessageDigest extends NativeRef implements Cloneable {

    public NativeMessageDigest(String algorithm) {
        super(NativeCrypto.mdCreateCtx(algorithm));
    }

    public NativeMessageDigest(long pointer) {
        super(pointer);
    }

    public void update(byte[] data) {
        Objects.requireNonNull(data);

        if (pointer == 0 || NativeCrypto.mdUpdate(pointer, data) != OPENSSL_SUCCESS) {
            throw new IllegalStateException("MD update operation failed");
        }
    }

    public byte[] doFinal() {
        byte[] result = pointer == 0
                ? null
                : NativeCrypto.mdFinal(pointer);
        if (result == null) {
            throw new IllegalStateException("MD final operation failed");
        }
        return result;
    }

    public byte[] doFinal(byte[] data) {
        update(data);
        return doFinal();
    }

    @Override
    public void close() {
        if (pointer != 0) {
            NativeCrypto.mdFreeCtx(pointer);
            super.close();
        }
    }

    public void reset() {
        if (pointer == 0 || NativeCrypto.mdReset(pointer) != OPENSSL_SUCCESS) {
            throw new IllegalStateException("MD reset operation failed");
        }
    }

    @Override
    protected NativeMessageDigest clone() {
        if (pointer == 0) {
            throw new IllegalStateException("Cannot clone MD instance");
        }

        long clonePointer = NativeCrypto.mdClone(pointer);
        if (clonePointer <= 0) {
            throw new IllegalStateException("MD clone operation failed");
        }
        return new NativeMessageDigest(clonePointer);
    }
}

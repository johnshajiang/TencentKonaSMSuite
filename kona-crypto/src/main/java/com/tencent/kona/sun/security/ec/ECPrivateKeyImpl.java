/*
 * Copyright (c) 2006, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.sun.security.ec;

import com.tencent.kona.sun.security.ec.point.AffinePoint;
import com.tencent.kona.sun.security.ec.point.MutablePoint;
import com.tencent.kona.sun.security.pkcs.PKCS8Key;
import com.tencent.kona.sun.security.util.ArrayUtil;
import com.tencent.kona.sun.security.util.DerInputStream;
import com.tencent.kona.sun.security.util.DerOutputStream;
import com.tencent.kona.sun.security.util.DerValue;
import com.tencent.kona.sun.security.util.ECParameters;
import com.tencent.kona.sun.security.util.ECUtil;
import com.tencent.kona.sun.security.x509.AlgorithmId;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * Key implementation for EC private keys.
 * <p>
 * ASN.1 syntax for EC private keys from SEC 1 v1.5 (draft):
 *
 * <pre>
 * EXPLICIT TAGS
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey OCTET STRING,
 *   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
 *   publicKey [1] BIT STRING OPTIONAL
 * }
 * </pre>
 *
 * We currently ignore the optional parameters and publicKey fields. We
 * require that the parameters are encoded as part of the AlgorithmIdentifier,
 * not in the private key structure.
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 */
public final class ECPrivateKeyImpl extends PKCS8Key implements ECPrivateKey {

    private static final long serialVersionUID = 88695385615075129L;

    private BigInteger s;       // private value
    private byte[] arrayS;      // private value as a little-endian array
    @SuppressWarnings("serial") // Type of field is not Serializable
    private ECParameterSpec params;

    /**
     * Construct a key from its encoding. Called by the ECKeyFactory.
     */
    public ECPrivateKeyImpl(byte[] encoded) throws InvalidKeyException {
        super(encoded);
        parseKeyBits();
    }

    /**
     * Construct a key from its components. Used by the
     * KeyFactory.
     */
    public ECPrivateKeyImpl(BigInteger s, ECParameterSpec params)
            throws InvalidKeyException {
        this.s = s;
        this.params = params;
        makeEncoding(s);

    }

    public ECPrivateKeyImpl(byte[] s, ECParameterSpec params)
            throws InvalidKeyException {
        this.arrayS = s.clone();
        this.params = params;
        makeEncoding(s);
    }

    private void makeEncoding(byte[] s) throws InvalidKeyException {
        algid = new AlgorithmId
                (AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(params));
        DerOutputStream out = new DerOutputStream();
        out.putInteger(1); // version 1
        byte[] privBytes = s.clone();
        ArrayUtil.reverse(privBytes);
        out.putOctetString(privBytes);
        Arrays.fill(privBytes, (byte) 0);
        DerValue val = DerValue.wrap(DerValue.tag_Sequence, out);
        key = val.toByteArray();
        val.clear();
    }

    private void makeEncoding(BigInteger s) throws InvalidKeyException {
        algid = new AlgorithmId(AlgorithmId.EC_oid,
                ECParameters.getAlgorithmParameters(params));
        byte[] sArr = s.toByteArray();
        // convert to fixed-length array
        int numOctets = (params.getOrder().bitLength() + 7) / 8;
        byte[] sOctets = new byte[numOctets];
        int inPos = Math.max(sArr.length - sOctets.length, 0);
        int outPos = Math.max(sOctets.length - sArr.length, 0);
        int length = Math.min(sArr.length, sOctets.length);
        System.arraycopy(sArr, inPos, sOctets, outPos, length);
        Arrays.fill(sArr, (byte) 0);

        DerOutputStream out = new DerOutputStream();
        out.putInteger(1); // version 1
        out.putOctetString(sOctets);
        Arrays.fill(sOctets, (byte) 0);
        DerValue val = DerValue.wrap(DerValue.tag_Sequence, out);
        key = val.toByteArray();
        val.clear();
    }

    // see JCA doc
    public String getAlgorithm() {
        return "EC";
    }

    // see JCA doc
    public BigInteger getS() {
        if (s == null) {
            byte[] arrCopy = arrayS.clone();
            ArrayUtil.reverse(arrCopy);
            s = new BigInteger(1, arrCopy);
            Arrays.fill(arrCopy, (byte)0);
        }
        return s;
    }

    private byte[] getArrayS0() {
        if (arrayS == null) {
            arrayS = ECUtil.sArray(getS(), params);
        }
        return arrayS;
    }

    public byte[] getArrayS() {
        return getArrayS0().clone();
    }

    // see JCA doc
    public ECParameterSpec getParams() {
        return params;
    }

    private void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(key);
            DerValue derValue = in.getDerValue();
            if (derValue.tag != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = derValue.data;
            int version = data.getInteger();
            if (version != 1) {
                throw new IOException("Version must be 1");
            }
            byte[] privData = data.getOctetString();
            ArrayUtil.reverse(privData);
            arrayS = privData;
            while (data.available() != 0) {
                DerValue value = data.getDerValue();
                if (value.isContextSpecific((byte) 0)) {
                    // ignore for now
                } else if (value.isContextSpecific((byte) 1)) {
                    // ignore for now
                } else {
                    throw new InvalidKeyException("Unexpected value: " + value);
                }
            }
            AlgorithmParameters algParams = this.algid.getParameters();
            if (algParams == null) {
                throw new InvalidKeyException("EC domain parameters must be "
                    + "encoded in the algorithm identifier");
            }
            params = algParams.getParameterSpec(ECParameterSpec.class);
        } catch (IOException e) {
            throw new InvalidKeyException("Invalid EC private key", e);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidKeyException("Invalid EC private key", e);
        }
    }

    @Override
    public PublicKey calculatePublicKey() {
        ECParameterSpec ecParams = getParams();
        ECOperations ops = ECOperations.forParameters(ecParams)
                .orElseThrow(ProviderException::new);
        MutablePoint pub = ops.multiply(ecParams.getGenerator(), getArrayS0());
        AffinePoint affPub = pub.asAffine();
        ECPoint w = new ECPoint(affPub.getX().asBigInteger(),
                affPub.getY().asBigInteger());
        try {
            return new ECPublicKeyImpl(w, ecParams);
        } catch (InvalidKeyException e) {
            throw new ProviderException(
                    "Unexpected error calculating public key", e);
        }
    }

    /**
     * Restores the state of this object from the stream.
     * <p>
     * Deserialization of this object is not supported.
     *
     * @param  stream the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    private void readObject(ObjectInputStream stream)
            throws IOException, ClassNotFoundException {
        throw new InvalidObjectException(
                "ECPrivateKeyImpl keys are not directly deserializable");
    }
}

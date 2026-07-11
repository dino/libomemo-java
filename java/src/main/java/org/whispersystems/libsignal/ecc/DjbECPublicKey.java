/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 * Copyright (c) 2026 Dino Team
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.libsignal.util.ByteUtil;

import java.math.BigInteger;
import java.util.Arrays;

public class DjbECPublicKey implements ECPublicKey {

  private final byte[] montPublicKey;
  private byte[] edPublicKey;

  DjbECPublicKey(byte[] montPublicKey) {
    this.montPublicKey = montPublicKey;
    this.edPublicKey = null;
  }

  DjbECPublicKey(byte[] montPublicKey, byte[] edPublicKey) {
    this.montPublicKey = montPublicKey;
    this.edPublicKey = edPublicKey;
  }

  @Override
  public byte[] serialize() {
    byte[] type = {Curve.DJB_TYPE};
    return ByteUtil.combine(type, montPublicKey);
  }

  public byte[] serialize2() {
    return getMontPublicKey();
  }

  public byte[] serializeEd() {
    return getEdPublicKey();
  }

  @Override
  public int getType() {
    return Curve.DJB_TYPE;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                      return false;
    if (!(other instanceof DjbECPublicKey)) return false;

    DjbECPublicKey that = (DjbECPublicKey)other;
    return Arrays.equals(this.montPublicKey, that.montPublicKey);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(montPublicKey);
  }

  @Override
  public int compareTo(ECPublicKey another) {
    return new BigInteger(montPublicKey).compareTo(new BigInteger(((DjbECPublicKey)another).montPublicKey));
  }

  public byte[] getPublicKey() {
    return montPublicKey;
  }

  public byte[] getMontPublicKey() {
    return montPublicKey;
  }

  public byte[] getEdPublicKey() {
    if (edPublicKey == null) {
      edPublicKey = Curve25519.getInstance(Curve25519.BEST).montToEd(montPublicKey);
    }
    return edPublicKey;
  }
}

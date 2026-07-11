/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 * Copyright (c) 2026 Dino Team
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

public interface ECPublicKey extends Comparable<ECPublicKey> {

  public static final int KEY_SIZE = 33;
  public static final int KEY_SIZE_OMEMO2 = 32;

  public byte[] serialize();
  public byte[] serialize2();
  public byte[] serializeEd();

  public int getType();
}

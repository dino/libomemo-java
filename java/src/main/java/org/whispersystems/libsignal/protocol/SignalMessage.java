/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * Copyright (c) 2026 Dino Team
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignalMessage implements CiphertextMessage {

  private static final int MAC_LENGTH = 8;
  private static final int MAC_LENGTH2 = 16;

  private final int         messageVersion;
  private final ECPublicKey senderRatchetKey;
  private final int         counter;
  private final int         previousCounter;
  private final byte[]      ciphertext;
  private final byte[]      serialized;
  private final byte[]      authenticatedPart;
  private final byte[]      mac;

  public SignalMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    this(serialized, false);
  }

  public SignalMessage(byte[] serialized, boolean version2) throws InvalidMessageException, LegacyMessageException {
    try {
      if (version2) {
        OMEMOProtos.OMEMOAuthenticatedMessage authenticatedMessage = OMEMOProtos.OMEMOAuthenticatedMessage.parseFrom(serialized);
        OMEMOProtos.OMEMOMessage message = OMEMOProtos.OMEMOMessage.parseFrom(authenticatedMessage.getMessage());

        this.serialized = serialized;
        this.senderRatchetKey = Curve.decodePointMont(message.getDhPub().toByteArray(), 0);
        this.messageVersion = 4;
        this.counter = message.getN();
        this.previousCounter = message.getPn();
        this.ciphertext = message.getCiphertext().toByteArray();
        this.authenticatedPart = authenticatedMessage.getMessage().toByteArray();
        this.mac = authenticatedMessage.getMac().toByteArray();
      } else {
        byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.length - 1 - MAC_LENGTH, MAC_LENGTH);
        byte     version      = messageParts[0][0];
        byte[]   message      = messageParts[1];

        if (ByteUtil.highBitsToInt(version) < CURRENT_VERSION) {
          throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
        }

        if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION) {
          throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
        }

        SignalProtos.SignalMessage whisperMessage = SignalProtos.SignalMessage.parseFrom(message);

        if (!whisperMessage.hasCiphertext() ||
            !whisperMessage.hasCounter() ||
            !whisperMessage.hasRatchetKey())
        {
          throw new InvalidMessageException("Incomplete message.");
        }

        this.serialized       = serialized;
        this.senderRatchetKey = Curve.decodePoint(whisperMessage.getRatchetKey().toByteArray(), 0);
        this.messageVersion   = ByteUtil.highBitsToInt(version);
        this.counter          = whisperMessage.getCounter();
        this.previousCounter  = whisperMessage.getPreviousCounter();
        this.ciphertext       = whisperMessage.getCiphertext().toByteArray();
        this.authenticatedPart = null;
        this.mac              = messageParts[2];
      }
    } catch (InvalidProtocolBufferException | InvalidKeyException | ParseException e) {
      throw new InvalidMessageException(e);
    }
  }

  private static byte[] serialize(int messageVersion, ECPublicKey senderRatchetKey, int counter, int previousCounter, byte[] ciphertext) {
    if (messageVersion >= 4) {
      return OMEMOProtos.OMEMOMessage.newBuilder()
              .setDhPub(ByteString.copyFrom(senderRatchetKey.serialize(), 1, 32))
              .setN(counter)
              .setPn(previousCounter)
              .setCiphertext(ByteString.copyFrom(ciphertext))
              .build().toByteArray();
    } else {
      return SignalProtos.SignalMessage.newBuilder()
              .setRatchetKey(ByteString.copyFrom(senderRatchetKey.serialize()))
              .setCounter(counter)
              .setPreviousCounter(previousCounter)
              .setCiphertext(ByteString.copyFrom(ciphertext))
              .build().toByteArray();
    }
  }

  private static byte[] serializeAuthenticated(byte[] message, byte[] mac) {
    return OMEMOProtos.OMEMOAuthenticatedMessage.newBuilder()
            .setMessage(ByteString.copyFrom(message))
            .setMac(ByteString.copyFrom(mac))
            .build().toByteArray();
  }

  public SignalMessage(int messageVersion, SecretKeySpec macKey, ECPublicKey senderRatchetKey,
                       int counter, int previousCounter, byte[] ciphertext,
                       IdentityKey senderIdentityKey,
                       IdentityKey receiverIdentityKey, boolean senderIsAlice)
  {
    byte[] version = {ByteUtil.intsToByteHighAndLow(messageVersion, CURRENT_VERSION)};
    byte[] message = serialize(messageVersion, senderRatchetKey, counter, previousCounter, ciphertext);

    this.messageVersion   = messageVersion;
    if (messageVersion == 4) {
      this.authenticatedPart = message;
      this.mac       = getMac(senderIdentityKey, receiverIdentityKey, macKey, authenticatedPart, senderIsAlice);
      this.serialized       = serializeAuthenticated(authenticatedPart, mac);
    } else {
      this.authenticatedPart = ByteUtil.combine(version, message);
      this.mac       = getMac(senderIdentityKey, receiverIdentityKey, macKey, authenticatedPart, senderIsAlice);
      this.serialized       = ByteUtil.combine(authenticatedPart, mac);
    }
    this.senderRatchetKey = senderRatchetKey;
    this.counter          = counter;
    this.previousCounter  = previousCounter;
    this.ciphertext       = ciphertext;
  }

  public ECPublicKey getSenderRatchetKey()  {
    return senderRatchetKey;
  }

  public int getMessageVersion() {
    return messageVersion;
  }

  public int getCounter() {
    return counter;
  }

  public byte[] getBody() {
    return ciphertext;
  }

  public void verifyMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey, boolean senderIsAlice)
      throws InvalidMessageException
  {
    byte[] serializedMessage, theirMac;
    if (messageVersion < 4) {
      byte[][] parts = ByteUtil.split(serialized, serialized.length - MAC_LENGTH, MAC_LENGTH);
      serializedMessage = parts[0];
      theirMac = parts[1];
    } else {
      serializedMessage = authenticatedPart;
      theirMac = mac;
    }
    byte[] ourMac = getMac(senderIdentityKey, receiverIdentityKey, macKey, serializedMessage, senderIsAlice);

    if (!MessageDigest.isEqual(ourMac, theirMac)) {
      throw new InvalidMessageException("Bad Mac!");
    }
  }

  private byte[] getMac(IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey,
                        SecretKeySpec macKey, byte[] serialized, boolean senderIsAlice)
  {
    try {
      int macLength = messageVersion < 4 ? MAC_LENGTH : MAC_LENGTH2;
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(macKey);

      if (messageVersion >= 4) {
        if (senderIsAlice) {
          mac.update(senderIdentityKey.getPublicKey().serializeEd());
          mac.update(receiverIdentityKey.getPublicKey().serializeEd());
        } else {
          mac.update(receiverIdentityKey.getPublicKey().serializeEd());
          mac.update(senderIdentityKey.getPublicKey().serializeEd());
        }
      } else {
        mac.update(senderIdentityKey.getPublicKey().serialize());
        mac.update(receiverIdentityKey.getPublicKey().serialize());
      }

      byte[] fullMac = mac.doFinal(serialized);
      return ByteUtil.trim(fullMac, macLength);
    } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public byte[] serialize() {
    return serialized;
  }

  @Override
  public int getType() {
    return CiphertextMessage.WHISPER_TYPE;
  }

  public static boolean isLegacy(byte[] message) {
    return message != null && message.length >= 1 &&
        ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
  }

}

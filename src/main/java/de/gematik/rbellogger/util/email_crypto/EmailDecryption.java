/*
 *
 * Copyright 2021-2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.rbellogger.util.email_crypto;

import de.gematik.rbellogger.key.IdentityBackedRbelKey;
import de.gematik.rbellogger.key.RbelKey;
import de.gematik.rbellogger.key.RbelKeyManager;
import de.gematik.rbellogger.util.RbelContent;
import de.gematik.rbellogger.util.email_crypto.elliptic_curve.BcException;
import de.gematik.rbellogger.util.email_crypto.elliptic_curve.ParseException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.directory.InvalidAttributesException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class EmailDecryption {

  private static final String OID_AES256_GCM = "2.16.840.1.101.3.4.1.46";
  private static final int STREAM_BUFFER_SIZE = 64 * 1024;

  public static Optional<RbelContent> decrypt(RbelContent message, RbelKeyManager keyManager)
      throws CMSException {
    var oAuthEnv = new CMSAuthEnvelopedData(message.toInputStream());
    AlgorithmIdentifier algCms = getAlgorithm(oAuthEnv);
    if (algCms.getAlgorithm().getId().equals(OID_AES256_GCM)) {
      return decryptOidAes256Gcm(oAuthEnv, algCms, keyManager);
    }
    return decryptDefault(message.toInputStream(), keyManager);
  }

  private static Optional<RbelContent> decryptDefault(InputStream message, RbelKeyManager keyManager)
      throws CMSException {
    CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(message);
    Collection<RecipientInformation> recipients =
        cmsEnvelopedData.getRecipientInfos().getRecipients();
    return decryptIfKeyForRecipientFound(
        recipients,
        keyManager,
        (recipient, privateKey) ->
            RbelContent.of(
                recipient.getContent(
                    new JceKeyTransEnvelopedRecipient(privateKey)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME))));
  }

  private static Optional<PrivateKey> findMatchingKey(
      RbelKeyManager keyManager, KeyTransRecipientId id) {
    return keyManager
        .getAllKeys()
        .filter(key -> serialNumberMatches(key, id.getSerialNumber()))
        .findFirst()
        .map(RbelKey::getKey)
        .map(PrivateKey.class::cast);
  }

  private static boolean serialNumberMatches(RbelKey key, BigInteger serialNumber) {
    if (key.isPrivateKey() && key instanceof IdentityBackedRbelKey identityBackedKey) {
      return serialNumber.equals(identityBackedKey.getCertificate().getSerialNumber());
    }
    return false;
  }

  private interface DecryptFunction {
    RbelContent decrypt(RecipientInformation recipient, PrivateKey privateKey)
        throws CMSException;
  }

  private static Optional<RbelContent> decryptIfKeyForRecipientFound(
      Collection<RecipientInformation> recipients,
      RbelKeyManager keyManager,
      DecryptFunction decryptFunction)
      throws CMSException {
    for (RecipientInformation recipient : recipients) {
      if (recipient.getRID() instanceof KeyTransRecipientId id) {
        var privateKey = findMatchingKey(keyManager, id);
        if (privateKey.isPresent()) {
          return Optional.of(decryptFunction.decrypt(recipient, privateKey.get()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<RbelContent> decryptOidAes256Gcm(
      CMSAuthEnvelopedData oAuthEnv, AlgorithmIdentifier algorithm, RbelKeyManager keyManager)
      throws CMSException {
    var recipients = oAuthEnv.getRecipientInfos().getRecipients();
    return decryptIfKeyForRecipientFound(
        recipients,
        keyManager,
        (recipient, privateKey) ->
            decryptOidAes256Gcm(
                oAuthEnv, (KeyTransRecipientInformation) recipient, algorithm, privateKey));
  }

  private static RbelContent decryptOidAes256Gcm(
      CMSAuthEnvelopedData oAuthEnv,
      KeyTransRecipientInformation recipient,
      AlgorithmIdentifier authEncAlg,
      PrivateKey privateKey) {
    byte[] plainSymKey = extractPlainSymKey(recipient, privateKey);
    byte[] pNonceValue = extractNonceValue(authEncAlg);
    RbelContent pSymEncoded = extractEncKeyData(oAuthEnv);
    byte[] pMac = oAuthEnv.getMac();
    if (checkExistenceOfPMacInEncValue(pSymEncoded, pMac)) {
      throw new RbelDecryptionException(
          "This PKCS7-Content does not contain the mac value in the encoded value!");
    }

    return decryptSymEncodedWithMac(pSymEncoded, pMac, pNonceValue, plainSymKey);
  }

  private static boolean checkExistenceOfPMacInEncValue(
      final RbelContent pSymEncoded, final byte[] pMac) {
    int size = pSymEncoded.size();
    byte[] subarraySymEncoded = pSymEncoded.toByteArray(Math.max(0, size - pMac.length), size);
    return Arrays.equals(subarraySymEncoded, pMac);
  }

  private static byte[] extractNonceValue(AlgorithmIdentifier authEncAlg) {
    DLSequence seq0 = (DLSequence) authEncAlg.getParameters();
    for (int iIndex = 0; iIndex < seq0.size(); iIndex++) {
      ASN1Encodable encTmp = seq0.getObjectAt(iIndex);
      if (encTmp instanceof DEROctetString derOctetString) {
        byte[] pNonceValue = derOctetString.getOctets();

        if (pNonceValue == null || pNonceValue.length == 0) {
          break;
        }
        return pNonceValue;
      }
    }
    throw new RbelDecryptionException("This PKCS7-Content has not a valid nonce value!");
  }

  private static RbelContent extractEncKeyData(final CMSAuthEnvelopedData oAuthEnv) {
    try {
      ContentInfo cInfo = oAuthEnv.toASN1Structure();
      if (cInfo == null) return RbelContent.of(new byte[0]);

      if (cInfo.getContent() instanceof DLSequence seq) {
        return extractEncKeyData(seq);
      } else if (cInfo.getContent() instanceof BERSequence seq) {
        return extractEncKeyData(seq);
      } else {
        throw new RbelDecryptionException(
            "This PKCS7-Content has not a valid encrypted Key value!");
      }
    } catch (IOException ex) {
      throw new RbelDecryptionException(ex.getMessage(), ex);
    }
  }

  private static RbelContent extractEncKeyData(BERSequence seq) throws IOException {
    for (int i = 0; i < seq.size(); i++) {
      ASN1Encodable encTmp = seq.getObjectAt(i);
      if (encTmp instanceof BERSequence seq2) {
        var bos = getAccumulatedOctets(seq2);
        if (bos.isPresent()) {
          return bos.get();
        }
      }
    }
    throw new RbelDecryptionException("Could not extract encoded key data");
  }

  private static Optional<RbelContent> getAccumulatedOctets(BERSequence seq)
      throws IOException {
    for (int i = 0; i < seq.size(); i++) {
      ASN1Encodable encTmp2 = seq.getObjectAt(i);
      if (encTmp2 instanceof org.bouncycastle.asn1.BERTaggedObject tagObj) {
        return getAccumulatedOctets(tagObj);
      }
    }
    return Optional.empty();
  }

  private static Optional<RbelContent> getAccumulatedOctets(BERTaggedObject tagObj)
      throws IOException {
    ASN1Primitive asn1Prim =
        ASN1Util.parseContextBaseUniversal(
                tagObj, tagObj.getTagNo(), tagObj.isExplicit(), BERTags.SEQUENCE)
            .toASN1Primitive();

    if (asn1Prim instanceof BERSequence berSeq) {
      Enumeration<DEROctetString> berOcts = berSeq.getObjects();
      // keep the chunks as they are, they are only joined lazily instead of being copied
      List<RbelContent> chunks = new ArrayList<>();
      while (berOcts.hasMoreElements()) {
        chunks.add(RbelContent.of(berOcts.nextElement().getOctets()));
      }
      return Optional.of(chunks.isEmpty() ? RbelContent.of(new byte[0]) : RbelContent.concat(chunks));
    } else {
      return Optional.empty();
    }
  }

  private static RbelContent extractEncKeyData(DLSequence seq) {
    for (int i = 0; i < seq.size(); i++) {
      ASN1Encodable encTmp = seq.getObjectAt(i);
      if (encTmp instanceof DLSequence seq2) {
        for (int j = 0; j < seq2.size(); j++) {
          ASN1Encodable encTmp2 = seq2.getObjectAt(j);
          if (encTmp2 instanceof DLTaggedObject tagObj) {
            return RbelContent.of(((DEROctetString) tagObj.getBaseObject()).getOctets());
          }
        }
      }
    }
    throw new RbelDecryptionException("This PKCS7-Content has not a valid encrypted Key value!");
  }

  private static AlgorithmIdentifier getAlgorithm(final CMSAuthEnvelopedData oAuthEnv) {
    try {
      Field recInfos = oAuthEnv.getClass().getDeclaredField("authEncAlg");
      recInfos.setAccessible(true); // NOSONAR
      return (AlgorithmIdentifier) recInfos.get(oAuthEnv);
    } catch (NoSuchFieldException | SecurityException | IllegalAccessException ex) {
      throw new RbelDecryptionException("Cannot extract algorithm", ex);
    }
  }

  private static byte[] extractPlainSymKey(
      KeyTransRecipientInformation recipient, PrivateKey privateKey) {
    try {
      if (recipient != null) {
        Field recInfos = recipient.getClass().getDeclaredField("info");
        recInfos.setAccessible(true); // NOSONAR
        KeyTransRecipientInfo keyInfo = (KeyTransRecipientInfo) recInfos.get(recipient);
        DEROctetString encKey = (DEROctetString) keyInfo.getEncryptedKey();

        if (encKey != null) {
          if (privateKey.getAlgorithm().equals("EC")) {
            return decryptTransportKeyEc(privateKey, encKey);
          } else {
            return decryptTransportKeyRsa(privateKey, encKey);
          }
        }
      }
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new RbelDecryptionException("Plain Symmetric Key could not be extracted", e);
    }
    throw new RbelDecryptionException("Plain Symmetric Key could not be extracted");
  }

  private static byte[] decryptTransportKeyRsa(
      final PrivateKey privateKey, final DEROctetString encKey) {
    try {
      AlgorithmParameterSpec spec =
          new OAEPParameterSpec(
              "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
      Cipher ci =
          Cipher.getInstance(
              "RSA/None/OAEPWithSHA256AndMGF1Padding", BouncyCastleProvider.PROVIDER_NAME);
      ci.init(Cipher.DECRYPT_MODE, privateKey, spec);

      return ci.doFinal(encKey.getOctets());
    } catch (IllegalBlockSizeException
        | BadPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | NoSuchAlgorithmException
        | NoSuchProviderException
        | NoSuchPaddingException e) {
      throw new RbelDecryptionException("Cannot decrypt RSA transport key", e);
    }
  }

  private static byte[] decryptTransportKeyEc(
      final PrivateKey privateKey, final DEROctetString encKey) {
    TransportKeyDecryptor transportKeyDecryptor = new TransportKeyDecryptor(privateKey);
    try {
      return transportKeyDecryptor.decryptTransportKey(encKey.getOctets());
    } catch (IOException
        | BcException
        | ParseException
        | InvalidAttributesException
        | DecoderException e) {
      throw new RbelDecryptionException("Cannot decrypt EC transport key", e);
    }
  }

  private static RbelContent decryptSymEncodedWithMac(
      RbelContent pSymEncoded, byte[] pMac, byte[] pNonceValue, byte[] plainSymKey) {
    try {
      GCMParameterSpec spec2 = new GCMParameterSpec(16 * 8, pNonceValue);
      SecretKey keySym = new SecretKeySpec(plainSymKey, "AES");
      Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
      cipher2.init(Cipher.DECRYPT_MODE, keySym, spec2);

      // The cipher expects the MAC appended to the encrypted value: stream both into it instead of
      // copying them into one large array first.
      List<RbelContent> plainText = new ArrayList<>();
      var buffer = new byte[STREAM_BUFFER_SIZE];
      try (InputStream encrypted = pSymEncoded.toInputStream()) {
        int read;
        while ((read = encrypted.read(buffer)) != -1) {
          var part = cipher2.update(buffer, 0, read);
          if (part != null) {
            plainText.add(RbelContent.of(part));
          }
        }
      }
      plainText.add(RbelContent.of(cipher2.doFinal(pMac)));
      return RbelContent.concat(plainText);
    } catch (IOException
        | NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new RbelDecryptionException("This PKCS7-Content could not be decrypted!", e);
    }
  }
}

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.gematik.rbellogger.key.IdentityBackedRbelKey;
import de.gematik.rbellogger.key.RbelKeyManager;
import de.gematik.rbellogger.util.RbelContent;
import de.gematik.test.tiger.common.pki.TigerPkiIdentityLoader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Random;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EmailDecryptionTest {

  private final String TEXT = "Text to be signed";
  private final byte[] BYTES = TEXT.getBytes();

  private RbelKeyManager getKeyManager(Path path) {
    RbelKeyManager keyManager = new RbelKeyManager();
    var identity = TigerPkiIdentityLoader.loadRbelPkiIdentityWithGuessedPassword(path.toFile());
    IdentityBackedRbelKey.generateRbelKeyPairForIdentity(identity).forEach(keyManager::addKey);
    return keyManager;
  }

  @Test
  @SneakyThrows
  void encryptAndDecryptWithRsaAndEccRecipient() {
    var message = BYTES;
    var keys1 = getKeyManager(Certs.REC1_P12_PATH);
    var keys2 = getKeyManager(Certs.ECC_P12);

    var encData = Files.readAllBytes(Paths.get("src/test/resources/crypto/encrypted0.encrypted"));

    byte[] decData1 = EmailDecryption.decrypt(RbelContent.of(encData), keys1).map(RbelContent::toByteArray).orElse(null);

    byte[] decData2 = EmailDecryption.decrypt(RbelContent.of(encData), keys2).map(RbelContent::toByteArray).orElse(null);

    assertArrayEquals(message, decData1);
    assertArrayEquals(message, decData2);
  }

  @Test
  void encryptAndDecprytWithOneRecipientAndECC() throws CMSException, IOException {
    var keys = getKeyManager(Certs.ECC_P12);

    var enc = Files.readAllBytes(Paths.get("src/test/resources/crypto/encrypted1.encrypted"));

    var decryptData = EmailDecryption.decrypt(RbelContent.of(enc), keys).map(RbelContent::toByteArray).orElse(null);

    assertArrayEquals(
        BYTES,
        decryptData,
        "The plain byte array and the encrypted and redecrypted byte are not equal.");
  }

  @Test
  void encryptAndDecprytWithOneRecipientAndRSA() throws Exception {
    var signer = getKeyManager(Certs.SIGNER1_P12);

    var enc = Files.readAllBytes(Paths.get("src/test/resources/crypto/encrypted2.encrypted"));

    var decryptData = EmailDecryption.decrypt(RbelContent.of(enc), signer).map(RbelContent::toByteArray).orElse(null);

    assertArrayEquals(
        BYTES,
        decryptData,
        "The plain byte array and the encrypted and redecrypted byte are not equal.");
  }

  /** AES-256-GCM authenticated-enveloped data, as sent by KIM clients, with an RSA-OAEP recipient. */
  @SneakyThrows
  private static byte[] encryptWithAes256Gcm(byte[] plain, X509Certificate recipient) {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    var sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    var oaepAlgorithm =
        new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_RSAES_OAEP,
            new RSAESOAEPparams(
                sha256,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256),
                new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))));
    var generator = new CMSAuthEnvelopedDataGenerator();
    generator.addRecipientInfoGenerator(
        new JceKeyTransRecipientInfoGenerator(recipient, oaepAlgorithm)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME));
    return generator
        .generate(
            new CMSProcessableByteArray(plain),
            (OutputAEADEncryptor)
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build())
        .getEncoded();
  }

  private static byte[] randomBytes(int size) {
    var bytes = new byte[size];
    new Random(42).nextBytes(bytes);
    return bytes;
  }

  @ParameterizedTest
  @ValueSource(ints = {65_536, 300_000})
  @SneakyThrows
  void decryptAes256GcmAuthEnvelopedData(int size) {
    var identity =
        TigerPkiIdentityLoader.loadRbelPkiIdentityWithGuessedPassword(
            Certs.REC1_P12_PATH.toFile());
    var plain = randomBytes(size);
    var encrypted = encryptWithAes256Gcm(plain, identity.getCertificate());

    var decrypted =
        EmailDecryption.decrypt(RbelContent.of(encrypted), getKeyManager(Certs.REC1_P12_PATH));

    assertArrayEquals(plain, decrypted.orElseThrow().toByteArray());
  }

  @Test
  @SneakyThrows
  void decryptAes256GcmAuthEnvelopedDataShouldFailWhenTheEncryptedDataWasChanged() {
    var identity =
        TigerPkiIdentityLoader.loadRbelPkiIdentityWithGuessedPassword(
            Certs.REC1_P12_PATH.toFile());
    var encrypted = encryptWithAes256Gcm(randomBytes(200_000), identity.getCertificate());
    encrypted[encrypted.length / 2] ^= 1; // somewhere inside of the encrypted content
    var keyManager = getKeyManager(Certs.REC1_P12_PATH);

    assertThatThrownBy(() -> EmailDecryption.decrypt(RbelContent.of(encrypted), keyManager))
        .isInstanceOf(RbelDecryptionException.class);
  }

  @Test
  @SneakyThrows
  void decryptAes256GcmAuthEnvelopedDataShouldReturnNothingWithoutMatchingKey() {
    var identity =
        TigerPkiIdentityLoader.loadRbelPkiIdentityWithGuessedPassword(
            Certs.REC1_P12_PATH.toFile());
    var encrypted = encryptWithAes256Gcm(randomBytes(100), identity.getCertificate());

    var decrypted =
        EmailDecryption.decrypt(RbelContent.of(encrypted), getKeyManager(Certs.SIGNER1_P12));

    assertThat(decrypted).isEmpty();
  }
}

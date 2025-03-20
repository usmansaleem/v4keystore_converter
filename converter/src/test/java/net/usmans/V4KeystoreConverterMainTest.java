// Copyright 2025, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package net.usmans;

import static net.usmans.V4keystore_converterMain.SECURE_RANDOM;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.stream.IntStream;
import net.usmans.V4keystore_converterMain.BulkloadingMode;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;
import tech.pegasys.teku.bls.BLSTestUtil;
import tech.pegasys.teku.bls.keystore.KeyStore;
import tech.pegasys.teku.bls.keystore.KeyStoreLoader;
import tech.pegasys.teku.bls.keystore.model.Cipher;
import tech.pegasys.teku.bls.keystore.model.CipherFunction;
import tech.pegasys.teku.bls.keystore.model.KdfFunction;
import tech.pegasys.teku.bls.keystore.model.KdfParam;
import tech.pegasys.teku.bls.keystore.model.KeyStoreData;
import tech.pegasys.teku.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.teku.bls.keystore.model.Pbkdf2PseudoRandomFunction;
import tech.pegasys.teku.bls.keystore.model.SCryptParam;

class V4KeystoreConverterMainTest {

  @TempDir static Path srcDir;
  @TempDir static Path passwordDir;

  @BeforeAll
  static void createTestKeystores() {
    var blsKeyPairs = IntStream.of(1, 2).mapToObj(BLSTestUtil::randomKeyPair).toList();
    var kdfParams = kdfParamQueue();
    var cipher = new Cipher(CipherFunction.AES_128_CTR, Bytes.random(16, SECURE_RANDOM));

    // create encrypted keystores
    List<KeyStoreData> encryptedKeystores =
        blsKeyPairs.stream()
            .map(
                blsKeyPair ->
                    KeyStore.encrypt(
                        blsKeyPair.getSecretKey().toBytes(),
                        blsKeyPair.getPublicKey().toBytesCompressed(),
                        "password",
                        "",
                        kdfParams.poll(),
                        cipher))
            .toList();

    // save encrypted keystores to files (WEB3SIGNER and NIMBUS modes)
    encryptedKeystores.forEach(
        keyStoreData -> {
          // web3signer mode
          try {
            var keystoreParentDir = srcDir.resolve(BulkloadingMode.WEB3SIGNER.name());
            keystoreParentDir.toFile().mkdirs();
            var keystoresFile =
                keystoreParentDir.resolve(keyStoreData.getPubkey().toHexString() + ".json");
            KeyStoreLoader.saveToFile(keystoresFile, keyStoreData);

            // write password to file
            var passwordParentDir = passwordDir.resolve(BulkloadingMode.WEB3SIGNER.name());
            passwordParentDir.toFile().mkdirs();
            var passwordFile =
                passwordParentDir.resolve(keyStoreData.getPubkey().toHexString() + ".txt");
            Files.writeString(passwordFile, "password");
          } catch (IOException e) {
            throw new RuntimeException(e);
          }

          // nimbus mode
          try {
            var keystoreParentDir =
                srcDir
                    .resolve(BulkloadingMode.NIMBUS.name())
                    .resolve(keyStoreData.getPubkey().toHexString());
            keystoreParentDir.toFile().mkdirs();
            var keystoreFile = keystoreParentDir.resolve("keystore.json");
            KeyStoreLoader.saveToFile(keystoreFile, keyStoreData);

            // write password to file
            var passwordParentDir = passwordDir.resolve(BulkloadingMode.NIMBUS.name());
            passwordParentDir.toFile().mkdirs();
            var passwordFile = passwordParentDir.resolve(keyStoreData.getPubkey().toHexString());
            Files.writeString(passwordFile, "password");
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
        });

    // add deposit_data-xyz.json that should be ignored by the converter
    try {
      Files.writeString(
          srcDir.resolve(BulkloadingMode.WEB3SIGNER.name()).resolve("deposit_data-123.json"), "{}");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static Queue<KdfParam> kdfParamQueue() {
    KdfParam kdfParam1 =
        new Pbkdf2Param(
            32, 128, Pbkdf2PseudoRandomFunction.HMAC_SHA256, Bytes32.random(SECURE_RANDOM));

    KdfParam kdfParam2 = new SCryptParam(32, 128, 1, 8, Bytes32.random(SECURE_RANDOM));
    LinkedList<KdfParam> kdfParamsQueue = new LinkedList<>();
    kdfParamsQueue.add(kdfParam1);
    kdfParamsQueue.add(kdfParam2);
    return kdfParamsQueue;
  }

  @Test
  void minimalOptionsTest(@TempDir Path destDir) throws Exception {
    V4keystore_converterMain app = new V4keystore_converterMain();
    CommandLine cmd = new CommandLine(app);

    StringWriter sw = new StringWriter();
    cmd.setOut(new PrintWriter(sw));

    int exitCode =
        cmd.execute(
            "--src",
            srcDir.resolve("WEB3SIGNER").toString(),
            "--password-src",
            passwordDir.resolve("WEB3SIGNER").toString(),
            "--dest",
            destDir.toString());

    assertThat(exitCode).isZero();

    Files.list(srcDir.resolve("WEB3SIGNER"))
        .filter(file -> !file.getFileName().toString().startsWith("deposit_data"))
        .forEach(
            keystoreFile -> {
              // load converted keystore
              final KeyStoreData convertedKeyStoreData =
                  KeyStoreLoader.loadFromFile(
                      destDir.resolve(keystoreFile.getFileName().toString()).toUri());

              assertThat(convertedKeyStoreData.getCrypto().getKdf().getKdfFunction())
                  .isEqualTo(KdfFunction.PBKDF2);

              KdfParam param = convertedKeyStoreData.getCrypto().getKdf().getParam();
              assertThat(param).isInstanceOf(Pbkdf2Param.class);
              assertThat(((Pbkdf2Param) param).getC()).isEqualTo(1);
            });
  }

  @Test
  void testNimbusModeWithMinimal(@TempDir Path destDir) throws IOException {
    V4keystore_converterMain app = new V4keystore_converterMain();
    CommandLine cmd = new CommandLine(app);

    StringWriter sw = new StringWriter();
    cmd.setOut(new PrintWriter(sw));

    int exitCode =
        cmd.execute(
            "--src",
            srcDir.resolve("NIMBUS").toString(),
            "--password-src",
            passwordDir.resolve("NIMBUS").toString(),
            "--dest",
            destDir.toString(),
            "--mode",
            "NIMBUS");

    assertThat(exitCode).isZero();

    Files.list(srcDir.resolve("NIMBUS"))
        .forEach(
            parentDir -> {
              // load converted keystore
              final KeyStoreData convertedKeyStoreData =
                  KeyStoreLoader.loadFromFile(
                      destDir
                          .resolve(parentDir.getFileName().toString())
                          .resolve("keystore.json")
                          .toUri());

              assertThat(convertedKeyStoreData.getCrypto().getKdf().getKdfFunction())
                  .isEqualTo(KdfFunction.PBKDF2);

              KdfParam param = convertedKeyStoreData.getCrypto().getKdf().getParam();
              assertThat(param).isInstanceOf(Pbkdf2Param.class);
              assertThat(((Pbkdf2Param) param).getC()).isEqualTo(1);
            });
  }

  @Test
  void testNimbusModeWithScrypt(@TempDir Path destDir) throws IOException {
    V4keystore_converterMain app = new V4keystore_converterMain();
    CommandLine cmd = new CommandLine(app);

    StringWriter sw = new StringWriter();
    cmd.setOut(new PrintWriter(sw));

    int exitCode =
        cmd.execute(
            "--src",
            srcDir.resolve("NIMBUS").toString(),
            "--password-src",
            passwordDir.resolve("NIMBUS").toString(),
            "--dest",
            destDir.toString(),
            "--mode",
            "NIMBUS",
            "--kdf-function",
            "SCRYPT",
            "-n",
            "16");

    assertThat(exitCode).isZero();

    Files.list(srcDir.resolve("NIMBUS"))
        .forEach(
            parentDir -> {
              // load converted keystore
              final KeyStoreData convertedKeyStoreData =
                  KeyStoreLoader.loadFromFile(
                      destDir
                          .resolve(parentDir.getFileName().toString())
                          .resolve("keystore.json")
                          .toUri());

              assertThat(convertedKeyStoreData.getCrypto().getKdf().getKdfFunction())
                  .isEqualTo(KdfFunction.SCRYPT);

              KdfParam param = convertedKeyStoreData.getCrypto().getKdf().getParam();
              assertThat(param).isInstanceOf(SCryptParam.class);
              assertThat(((SCryptParam) param).getN()).isEqualTo(16);
            });
  }
}

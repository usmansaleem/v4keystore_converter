// Copyright 2025, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package net.usmans;

import static com.google.common.io.Files.*;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import me.tongfei.progressbar.ProgressBar;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import tech.pegasys.teku.bls.keystore.KeyStore;
import tech.pegasys.teku.bls.keystore.KeyStoreLoader;
import tech.pegasys.teku.bls.keystore.model.Cipher;
import tech.pegasys.teku.bls.keystore.model.CipherFunction;
import tech.pegasys.teku.bls.keystore.model.KdfFunction;
import tech.pegasys.teku.bls.keystore.model.KeyStoreData;
import tech.pegasys.teku.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.teku.bls.keystore.model.Pbkdf2PseudoRandomFunction;
import tech.pegasys.teku.bls.keystore.model.SCryptParam;

@Command(
    name = "converter",
    mixinStandardHelpOptions = true,
    version = "0.2.0",
    description = "Convert KDF function parameters of BLS V4 keystores",
    sortOptions = false,
    sortSynopsis = false)
public class V4keystore_converterMain implements Callable<Integer> {
  static final SecureRandom SECURE_RANDOM = new SecureRandom();

  @Option(
      names = {"--src"},
      paramLabel = "<PATH>",
      description = "Source directory containing v4 keystores",
      required = true)
  private Path source;

  @Option(
      names = {"--password-src"},
      paramLabel = "<PATH>",
      description = "Path to directory containing passwords files.",
      required = true)
  private Path passwordPath;

  @Option(
      names = {"--dest"},
      paramLabel = "<PATH>",
      description = "Destination directory where converted v4 keystores will be placed.",
      required = true)
  private Path destination;

  @Option(
      names = {"--mode"},
      paramLabel = "<MODE>",
      description =
          "Keystores Bulk-loading mode. WEB3SIGNER mode expects [<pk>.json | <pk>.txt] "
              + "while NIMBUS mode expects [<pk>/keystore.json | <pk>] as keystore/password file pair. "
              + "Valid Values: ${COMPLETION-CANDIDATES}. Defaults to: ${DEFAULT-VALUE}")
  private BulkloadingMode mode = BulkloadingMode.WEB3SIGNER;

  @Option(
      names = {"--kdf-function"},
      paramLabel = "<KDF>",
      description =
          "Kdf Function to convert to. Valid values: ${COMPLETION-CANDIDATES}. Defaults to: ${DEFAULT-VALUE}")
  private KdfFunction kdfFunction = KdfFunction.PBKDF2;

  @ArgGroup(validate = false, heading = "PBKDF2 Options%n")
  PBKDFOptions pbkdfOptions = new PBKDFOptions();

  @ArgGroup(validate = false, heading = "SCRYPT Options%n")
  SCRYPTOptions scryptOptions = new SCRYPTOptions();

  static class PBKDFOptions {
    @Option(
        names = {"-c"},
        paramLabel = "<INTEGER>",
        description =
            "Iterative count parameter. Required for PBKDF2 kdf function. Defaults to ${DEFAULT-VALUE}.")
    Integer c = 1;
  }

  static class SCRYPTOptions {
    @Option(
        names = {"-n"},
        paramLabel = "<INTEGER>",
        description =
            "CPU/memory cost parameter. Required for SCRYPT kdf function. Defaults to ${DEFAULT-VALUE}.")
    Integer n = 2;

    @Option(
        names = {"-p"},
        paramLabel = "<INTEGER>",
        description =
            "Parallelization parameter. Required for SCRYPT kdf function. Defaults to ${DEFAULT-VALUE}.")
    Integer p = 1;

    @Option(
        names = {"-r"},
        paramLabel = "<INTEGER>",
        description =
            "Block size parameter. Required for SCRYPT kdf function. Defaults to ${DEFAULT-VALUE}.")
    Integer r = 8;
  }

  @Spec private CommandSpec spec; // will be populated by PicoCli at runtime

  enum BulkloadingMode {
    WEB3SIGNER,
    NIMBUS
  }

  record KeyStoreRecord(KeyStoreData keyStoreData, Bytes privateKey, String password) {}

  public static void main(String[] args) {
    int exitCode =
        new CommandLine(new V4keystore_converterMain())
            .setCaseInsensitiveEnumValuesAllowed(true)
            .execute(args);
    System.exit(exitCode);
  }

  @Override
  public Integer call() {
    validateCliParams();

    System.out.println("Reading source paths ...");
    List<Path> srcPaths = getKeystoresPath();

    final Map<Path, KeyStoreRecord> decryptedKeystores = decryptKeystores(srcPaths);

    convertDecryptedKeystores(decryptedKeystores);
    System.out.println("Conversion completed successfully.");
    return 0;
  }

  /**
   * Read keystore paths from source directory. Web3Signer has publickey.json as keystore files.
   * Nimbus has publickey/keystore.json as keystore files. The {@code Files.list} method does not
   * run in parallel, hence we only read the keystores Paths that will be processed later.
   *
   * @return List of keystore paths
   */
  private List<Path> getKeystoresPath() {
    try (Stream<Path> srcFiles = Files.list(source)) {
      return switch (mode) {
        case WEB3SIGNER ->
            srcFiles
                .filter(
                    path ->
                        Files.isRegularFile(path)
                            && path.getFileName().toString().endsWith(".json"))
                .toList();
        case NIMBUS ->
            srcFiles.filter(Files::isDirectory).map(path -> path.resolve("keystore.json")).toList();
      };
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Decrypt v4 keystores.
   *
   * @param keystorePaths The keystore paths that will be decrypted.
   * @return Map of encrypted keystore path and decrypted keystore data.
   */
  private Map<Path, KeyStoreRecord> decryptKeystores(final List<Path> keystorePaths) {
    return ProgressBar.wrap(keystorePaths.parallelStream(), "Decrypting")
        .map(
            keystorePath -> {
              var password = getPassword(keystorePath);
              try {
                final KeyStoreData keyStoreData = KeyStoreLoader.loadFromFile(keystorePath.toUri());
                final Bytes privateKey = KeyStore.decrypt(password, keyStoreData);
                return Map.entry(
                    keystorePath, new KeyStoreRecord(keyStoreData, privateKey, password));
              } catch (final RuntimeException e) {
                System.err.printf("Error decrypting keystore: %s%n", e.getMessage());
                return null;
              }
            })
        .filter(Objects::nonNull)
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  private void convertDecryptedKeystores(final Map<Path, KeyStoreRecord> decryptedKeystores) {
    try {
      Files.createDirectories(destination);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    ProgressBar.wrap(decryptedKeystores.entrySet().parallelStream(), "Converting")
        .forEach(
            entry -> {
              try {
                var kdfParam =
                    switch (kdfFunction) {
                      case PBKDF2 ->
                          new Pbkdf2Param(
                              32,
                              pbkdfOptions.c,
                              Pbkdf2PseudoRandomFunction.HMAC_SHA256,
                              Bytes32.random(SECURE_RANDOM));
                      case SCRYPT ->
                          new SCryptParam(
                              32,
                              scryptOptions.n,
                              scryptOptions.p,
                              scryptOptions.r,
                              Bytes32.random(SECURE_RANDOM));
                    };

                var cipher =
                    new Cipher(CipherFunction.AES_128_CTR, Bytes.random(16, SECURE_RANDOM));

                var pubKey = entry.getValue().keyStoreData().getPubkey();
                final KeyStoreData encrypted =
                    KeyStore.encrypt(
                        entry.getValue().privateKey(),
                        pubKey,
                        entry.getValue().password(),
                        entry.getValue().keyStoreData().getPath(),
                        kdfParam,
                        cipher);

                var keystoreDestDir =
                    switch (mode) {
                      case WEB3SIGNER -> destination;
                      case NIMBUS ->
                          Files.createDirectory(destination.resolve(pubKey.toHexString()));
                    };

                KeyStoreLoader.saveToFile(
                    keystoreDestDir.resolve(entry.getKey().getFileName()), encrypted);
              } catch (RuntimeException | IOException e) {
                System.err.printf("Error while converting keystore: %s%n", e.getMessage());
              }
            });
  }

  /**
   * Read password of keystore file. Web3Signer uses <pk>.txt while Nimbus uses <pk> without
   * extension as password.
   *
   * @param keystorePath The keystore path
   * @return The password
   */
  private String getPassword(Path keystorePath) {
    var passwordFileName =
        switch (mode) {
          case WEB3SIGNER ->
              Path.of(getNameWithoutExtension(keystorePath.getFileName().toString()) + ".txt");
          case NIMBUS -> keystorePath.getParent().getFileName();
        };

    try {
      return Files.readString(passwordPath.resolve(passwordFileName));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private void validateCliParams() {
    if (kdfFunction == KdfFunction.PBKDF2 && pbkdfOptions.c <= 0) {
      throw new ParameterException(spec.commandLine(), "-c must be a positive integer.");
    }

    if (kdfFunction == KdfFunction.SCRYPT) {
      if (scryptOptions.n <= 1) {
        throw new ParameterException(
            spec.commandLine(), "-n must be a positive integer and must be a power of 2.");
      }

      if (scryptOptions.p <= 0) {
        throw new ParameterException(spec.commandLine(), "-p must be a positive integer.");
      }

      if (scryptOptions.r <= 0) {
        throw new ParameterException(spec.commandLine(), "-r must be a positive integer.");
      }
    }
  }
}

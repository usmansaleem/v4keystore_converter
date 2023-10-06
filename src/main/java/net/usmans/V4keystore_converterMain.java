package net.usmans;

import com.google.common.base.Stopwatch;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
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

import static com.google.common.io.Files.getNameWithoutExtension;
import static java.util.Collections.emptyMap;

@Command(name = "v4keystore_converter", mixinStandardHelpOptions = true, version = "0.1.0",
        description = "Convert KDF function parameters of EIP-2335 v4 keystores"
)
public class V4keystore_converterMain implements Callable<Integer> {

    private static final Logger LOG = LoggerFactory.getLogger("Main");
    @Option(names = {"--kdf-function"}, paramLabel = "<KDF>", description = "Kdf Function to convert to. Valid values: ${COMPLETION-CANDIDATES}. Defaults to: S{DEFAULT-VALUE}")
    private final KdfFunction kdfFunction = KdfFunction.PBKDF2;
    @Option(names = {"-c"}, paramLabel = "<INTEGER>", description = "Iterative count parameter. Required for PBKDF2 kdf function.")
    private final Integer c = 1;
    @Option(names = {"-n"}, paramLabel = "<INTEGER>", description = "CPU/memory cost parameter. Required for SCRYPT kdf function.")
    private final Integer n = 1;
    @Option(names = {"-p"}, paramLabel = "<INTEGER>", description = "Parallelization parameter. Required for SCRYPT kdf function.")
    private final Integer p = 1;
    @Option(names = {"-r"}, paramLabel = "<INTEGER>", description = "Block size parameter. Defaults to ${DEFAULT-VALUE}. Required for SCRYPT kdf function.")
    private final Integer r = 8;
    @Option(names = {"--src"}, paramLabel = "<PATH>", description = "Source directory containing v4 keystores", required = true)
    private Path source;
    @Option(names = {"--dest"}, paramLabel = "<PATH>", description = "Destination directory where v4 keystores will be generated.", required = true)
    private Path destination;
    @Option(names = {"--password-path"}, paramLabel = "<PATH>", description = "Path to password file or directory containing matching password files with .txt extensions.", required = true)
    private Path passwordPath;
    @CommandLine.Spec
    private CommandSpec spec; //will be populated by PicoCli at runtime

    public static void main(String[] args) {
        int exitCode = new CommandLine(new V4keystore_converterMain())
                .setCaseInsensitiveEnumValuesAllowed(true)
                .execute(args);
        System.exit(exitCode);
    }

    private static Map<Path, String> getPasswords(List<Path> srcPaths, Path passwordPath) {
        final String singlePassword;
        if (passwordPath.toFile().isFile()) {
            try {
                singlePassword = Files.readString(passwordPath);
            } catch (IOException e) {
                LOG.error("Error reading from password file {}", passwordPath);
                return emptyMap();
            }
        } else {
            singlePassword = null;
        }
        return srcPaths.parallelStream().map(path -> {
                    try {
                        return Map.entry(path, singlePassword != null ? singlePassword : Files.readString(passwordPath.resolve(getNameWithoutExtension(path.toString()) + ".txt")));
                    } catch (IOException e) {
                        LOG.error("Error reading from password file: {}", e.getMessage());
                        return null;
                    }
                }).filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public Integer call() {
        if (kdfFunction == KdfFunction.PBKDF2 && c <= 0) {
            throw new ParameterException(spec.commandLine(), "-c must be a positive integer.");
        }

        if (kdfFunction == KdfFunction.SCRYPT) {
            if (n <= 0) {
                throw new ParameterException(spec.commandLine(), "-n must be a positive integer.");
            }

            if (p <= 0) {
                throw new ParameterException(spec.commandLine(), "-p must be a positive integer.");
            }

            if (r <= 0) {
                throw new ParameterException(spec.commandLine(), "-r must be a positive integer.");
            }
        }
        final Stopwatch stopwatch = Stopwatch.createStarted();
        // iterate the source folder and obtain all the keystore paths. Files.list does not provide parallel stream.
        LOG.info("Reading .json paths from {}", source);
        List<Path> srcPaths;
        try (Stream<Path> srcFiles = Files.list(source)) {
            srcPaths = srcFiles.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".json"))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        // associate passwords with the v4 keystores
        LOG.info("Reading password(s) from {}", passwordPath);
        final Map<Path, String> passwordMap = getPasswords(srcPaths, passwordPath);

        LOG.info("Decrypting keystores ...");
        final Map<Path, KeyStoreRecord> decryptedKeystores = passwordMap.entrySet().parallelStream().map(entry -> {
                    try {
                        final KeyStoreData keyStoreData = KeyStoreLoader.loadFromFile(entry.getKey().toUri());
                        final Bytes privateKey = KeyStore.decrypt(entry.getValue(), keyStoreData);
                        return Map.entry(entry.getKey(), new KeyStoreRecord(keyStoreData, privateKey, entry.getValue()));
                    } catch (final RuntimeException e) {
                        LOG.error("Error decrypting keystore: {}", e.getMessage());
                        return null;
                    }
                }).filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        LOG.info("Time taken: {}", stopwatch);

        LOG.info("Converting keystores ...");
        final SecureRandom secureRandom = new SecureRandom();
        decryptedKeystores.entrySet().parallelStream().forEach(entry -> {
            try {
                final KdfParam kdfParam;
                if (kdfFunction == KdfFunction.PBKDF2) {
                    kdfParam =
                            new Pbkdf2Param(
                                    32, c, Pbkdf2PseudoRandomFunction.HMAC_SHA256, Bytes32.random(secureRandom));
                } else {
                    kdfParam = new SCryptParam(32, n, p, r, Bytes32.random(secureRandom));
                }

                final Cipher cipher = new Cipher(CipherFunction.AES_128_CTR, Bytes.random(16, secureRandom));
                final KeyStoreData encrypted = KeyStore.encrypt(entry.getValue().privateKey(), entry.getValue().keyStoreData().getPubkey(), entry.getValue().password(), entry.getValue().keyStoreData().getPath(), kdfParam, cipher);

                KeyStoreLoader.saveToFile(destination.resolve(entry.getKey().getFileName()), encrypted);
            } catch (RuntimeException | IOException e) {
                LOG.error("Error converting keystores {}", e.getMessage());
            }
        });

        LOG.info("Done. Total Time taken: {}", stopwatch);

        // encrypt using supplied function
        return 0;
    }

}
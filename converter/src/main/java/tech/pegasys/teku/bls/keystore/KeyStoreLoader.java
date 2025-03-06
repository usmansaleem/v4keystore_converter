// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import tech.pegasys.teku.bls.keystore.model.KdfParam;
import tech.pegasys.teku.bls.keystore.model.KeyStoreData;

/** Provide utility methods to load/store BLS KeyStore from json format */
public class KeyStoreLoader {
  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper()
          .registerModule(new KeyStoreBytesModule())
          .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  public static KeyStoreData loadFromString(final String keystoreString) {
    try {
      final KeyStoreData keyStoreData = OBJECT_MAPPER.readValue(keystoreString, KeyStoreData.class);
      keyStoreData.validate();
      return keyStoreData;
    } catch (final JsonParseException e) {
      throw new KeyStoreValidationException("Invalid KeyStore: " + e.getMessage(), e);
    } catch (final JsonMappingException e) {
      throw convertToKeyStoreValidationException(e);
    } catch (final IOException e) {
      throw new KeyStoreValidationException(
          "Unexpected IO error while reading KeyStore: " + e.getMessage(), e);
    }
  }

  public static KeyStoreData loadFromFile(final URI keystoreFile)
      throws KeyStoreValidationException {
    checkNotNull(keystoreFile, "KeyStore path cannot be null");

    try {
      return loadFromUrl(keystoreFile.toURL());
    } catch (final MalformedURLException e) {
      throw new KeyStoreValidationException("Invalid KeyStore: " + e.getMessage(), e);
    }
  }

  public static KeyStoreData loadFromUrl(final URL keystoreFile)
      throws KeyStoreValidationException {
    checkNotNull(keystoreFile, "KeyStore path cannot be null");

    try {
      final KeyStoreData keyStoreData = OBJECT_MAPPER.readValue(keystoreFile, KeyStoreData.class);
      keyStoreData.validate();
      return keyStoreData;
    } catch (final JsonParseException e) {
      throw new KeyStoreValidationException("Invalid KeyStore: " + e.getMessage(), e);
    } catch (final JsonMappingException e) {
      throw convertToKeyStoreValidationException(e);
    } catch (final FileNotFoundException e) {
      throw new KeyStoreValidationException("KeyStore file not found: " + keystoreFile, e);
    } catch (final IOException e) {
      throw new KeyStoreValidationException(
          "Unexpected IO error while reading KeyStore: " + e.getMessage(), e);
    }
  }

  private static KeyStoreValidationException convertToKeyStoreValidationException(
      final JsonMappingException e) {
    final String cause;
    if (e.getCause() instanceof KeyStoreValidationException) {
      // this is wrapped because it is raised from custom deserializer in KeyStoreBytesModule to
      // validate enums
      throw (KeyStoreValidationException) e.getCause();
    }

    if (e instanceof InvalidTypeIdException) {
      cause = getKdfFunctionErrorMessage((InvalidTypeIdException) e);
    } else {
      cause = "Invalid KeyStore: " + e.getMessage();
    }
    return new KeyStoreValidationException(cause, e);
  }

  private static String getKdfFunctionErrorMessage(final InvalidTypeIdException e) {
    if (e.getBaseType().getRawClass() == KdfParam.class) {
      return "Kdf function [" + e.getTypeId() + "] is not supported.";
    }
    return "Invalid KeyStore: " + e.getMessage();
  }

  public static void saveToFile(final Path keystoreFile, final KeyStoreData keyStoreData)
      throws IOException {
    checkNotNull(keystoreFile, "KeyStore path cannot be null");
    checkNotNull(keyStoreData, "KeyStore data cannot be null");

    Files.writeString(keystoreFile, toJson(keyStoreData), UTF_8);
  }

  private static String toJson(final KeyStoreData keyStoreData) {
    try {
      return KeyStoreLoader.OBJECT_MAPPER
          .writerWithDefaultPrettyPrinter()
          .writeValueAsString(keyStoreData);
    } catch (final JsonProcessingException e) {
      throw new KeyStoreValidationException(
          "Error in converting KeyStore to Json: " + e.getMessage(), e);
    }
  }
}

// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.keystore.KeyStoreValidationException;

public class Cipher {
  private final CipherFunction cipherFunction;
  private final CipherParam cipherParam;
  private final Bytes message;

  @JsonCreator
  public Cipher(
      @JsonProperty(value = "function", required = true) final CipherFunction cipherFunction,
      @JsonProperty(value = "params", required = true) final CipherParam cipherParam,
      @JsonProperty(value = "message", required = true) final Bytes message) {
    this.cipherFunction = cipherFunction;
    this.cipherParam = cipherParam;
    this.message = message;
  }

  public Cipher(final CipherFunction cipherFunction, final Bytes ivParam) {
    this(cipherFunction, new CipherParam(ivParam), Bytes.EMPTY);
  }

  public Cipher(final Bytes ivParam) {
    this(CipherFunction.AES_128_CTR, new CipherParam(ivParam), Bytes.EMPTY);
  }

  @JsonProperty(value = "function")
  public CipherFunction getCipherFunction() {
    return cipherFunction;
  }

  @JsonProperty(value = "params")
  public CipherParam getCipherParam() {
    return cipherParam;
  }

  @JsonProperty(value = "message")
  public Bytes getMessage() {
    return message;
  }

  public void validate() throws KeyStoreValidationException {
    // In case of CTR/SIC, the size of IV is between 8 bytes and 16 bytes
    if (cipherParam.getIv().size() < 8 || cipherParam.getIv().size() > 16) {
      throw new KeyStoreValidationException(
          "Initialization Vector parameter iv size must be >= 8 and <= 16");
    }
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("function", cipherFunction)
        .add("params", cipherParam)
        .add("message", message)
        .toString();
  }
}

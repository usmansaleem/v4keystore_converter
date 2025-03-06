// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;

public class Crypto {
  private final Kdf kdf;
  private final Checksum checksum;
  private final Cipher cipher;

  @JsonCreator
  public Crypto(
      @JsonProperty(value = "kdf", required = true) final Kdf kdf,
      @JsonProperty(value = "checksum", required = true) final Checksum checksum,
      @JsonProperty(value = "cipher", required = true) final Cipher cipher) {
    this.kdf = kdf;
    this.checksum = checksum;
    this.cipher = cipher;
  }

  @JsonProperty(value = "kdf")
  public Kdf getKdf() {
    return kdf;
  }

  @JsonProperty(value = "checksum")
  public Checksum getChecksum() {
    return checksum;
  }

  @JsonProperty(value = "cipher")
  public Cipher getCipher() {
    return cipher;
  }

  public void validate() {
    kdf.validate();
    cipher.validate();
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("kdf", kdf)
        .add("checksum", checksum)
        .add("cipher", cipher)
        .toString();
  }
}

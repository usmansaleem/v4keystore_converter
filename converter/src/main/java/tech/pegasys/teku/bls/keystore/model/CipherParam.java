// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import org.apache.tuweni.bytes.Bytes;

public class CipherParam {
  private final Bytes iv;

  @JsonCreator
  public CipherParam(@JsonProperty(value = "iv", required = true) final Bytes iv) {
    this.iv = iv;
  }

  @JsonProperty(value = "iv")
  public Bytes getIv() {
    return iv;
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this).add("iv", iv).toString();
  }
}

// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum CipherFunction {
  AES_128_CTR("aes-128-ctr");

  private final String jsonValue;

  CipherFunction(final String jsonValue) {
    this.jsonValue = jsonValue;
  }

  @JsonValue
  public String getJsonValue() {
    return this.jsonValue;
  }
}

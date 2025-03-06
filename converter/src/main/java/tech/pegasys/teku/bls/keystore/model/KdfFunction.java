// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum KdfFunction {
  PBKDF2("pbkdf2"),
  SCRYPT("scrypt");

  private final String jsonValue;

  KdfFunction(final String jsonValue) {
    this.jsonValue = jsonValue;
  }

  @JsonValue
  public String getJsonValue() {
    return this.jsonValue;
  }
}

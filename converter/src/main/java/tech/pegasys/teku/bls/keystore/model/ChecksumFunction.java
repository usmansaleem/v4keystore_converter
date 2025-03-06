// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ChecksumFunction {
  SHA256("sha256");
  private final String jsonValue;

  ChecksumFunction(final String jsonValue) {
    this.jsonValue = jsonValue;
  }

  @JsonValue
  public String getJsonValue() {
    return this.jsonValue;
  }
}

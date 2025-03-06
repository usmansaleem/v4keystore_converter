// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum Pbkdf2PseudoRandomFunction {
  HMAC_SHA256("hmac-sha256");
  private final String jsonValue;

  Pbkdf2PseudoRandomFunction(final String jsonValue) {
    this.jsonValue = jsonValue;
  }

  @JsonValue
  public String getJsonValue() {
    return this.jsonValue;
  }
}

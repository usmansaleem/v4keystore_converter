// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Placeholder for empty params */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EmptyParam {
  public EmptyParam() {}

  @Override
  public String toString() {
    return "";
  }
}

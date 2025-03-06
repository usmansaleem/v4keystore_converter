// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public class Checksum {
  private final ChecksumFunction checksumFunction;
  private final EmptyParam emptyParam;
  private final Bytes message;

  @JsonCreator
  public Checksum(
      @JsonProperty(value = "function", required = true) final ChecksumFunction checksumFunction,
      @JsonProperty(value = "params", required = true) final EmptyParam emptyParam,
      @JsonProperty(value = "message", required = true) final Bytes message) {
    this.checksumFunction = checksumFunction;
    this.emptyParam = emptyParam;
    this.message = message;
  }

  public Checksum(final Bytes message) {
    this(ChecksumFunction.SHA256, new EmptyParam(), message);
  }

  @JsonProperty(value = "function")
  public ChecksumFunction getChecksumFunction() {
    return checksumFunction;
  }

  @JsonProperty(value = "params")
  public EmptyParam getEmptyParam() {
    return emptyParam;
  }

  @JsonProperty(value = "message")
  public Bytes getMessage() {
    return message;
  }

  @Override
  public String toString() {
    return "Checksum{"
        + "checksumFunction="
        + checksumFunction
        + ", emptyParam="
        + emptyParam
        + ", message="
        + message
        + '}';
  }
}

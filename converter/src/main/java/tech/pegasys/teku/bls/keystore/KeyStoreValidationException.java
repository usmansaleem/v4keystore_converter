// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore;

public class KeyStoreValidationException extends RuntimeException {
  public KeyStoreValidationException() {
    super();
  }

  public KeyStoreValidationException(final String message) {
    super(message);
  }

  public KeyStoreValidationException(final String message, final Throwable cause) {
    super(message, cause);
  }

  public KeyStoreValidationException(final Throwable cause) {
    super(cause);
  }
}

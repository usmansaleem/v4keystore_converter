// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.text.Normalizer;
import java.text.Normalizer.Form;
import org.apache.tuweni.bytes.Bytes;

public class PasswordUtils {

  public static Bytes normalizePassword(final String password) {
    final String normalizedPassword = Normalizer.normalize(password, Form.NFKD);
    final int[] filteredCodepoints =
        normalizedPassword.chars().filter(c -> !isControlCode(c)).toArray();
    final byte[] utf8Password =
        new String(filteredCodepoints, 0, filteredCodepoints.length).getBytes(UTF_8);
    return Bytes.wrap(utf8Password);
  }

  private static boolean isControlCode(final int c) {
    return isC0(c) || isC1(c) || c == 0x7F;
  }

  private static boolean isC1(final int c) {
    return 0x80 <= c && c <= 0x9F;
  }

  private static boolean isC0(final int c) {
    return 0x00 <= c && c <= 0x1F;
  }
}

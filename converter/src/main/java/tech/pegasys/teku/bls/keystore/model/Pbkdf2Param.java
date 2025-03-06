// Copyright 2020, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package tech.pegasys.teku.bls.keystore.model;

import static com.google.common.base.Preconditions.checkNotNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import tech.pegasys.teku.bls.keystore.KeyStoreValidationException;

public class Pbkdf2Param extends KdfParam {

  private final Integer c;
  private final Pbkdf2PseudoRandomFunction prf;

  /**
   * PBKDF2 Key Derivation Function
   *
   * @param dklen The length of key to generate
   * @param c The iteration count
   * @param prf The pseudo random function i.e. hash digest to use.
   * @param salt The salt to use
   */
  @JsonCreator
  public Pbkdf2Param(
      @JsonProperty(value = "dklen", required = true) final int dklen,
      @JsonProperty(value = "c", required = true) final int c,
      @JsonProperty(value = "prf", required = true) final Pbkdf2PseudoRandomFunction prf,
      @JsonProperty(value = "salt", required = true) final Bytes salt) {
    super(dklen, salt);
    this.c = c;
    this.prf = prf;
  }

  @Override
  public void validate() throws KeyStoreValidationException {
    super.validate();
    if (c < 1) {
      throw new KeyStoreValidationException("Iteration Count parameter c must be >= 1");
    }
  }

  @JsonProperty(value = "c")
  public Integer getC() {
    return c;
  }

  @JsonProperty(value = "prf")
  public Pbkdf2PseudoRandomFunction getPrf() {
    return prf;
  }

  @Override
  @JsonIgnore
  public KdfFunction getKdfFunction() {
    return KdfFunction.PBKDF2;
  }

  @Override
  protected Bytes generateDecryptionKey(final Bytes password) {
    checkNotNull(password, "Password cannot be null");
    final PKCS5S2ParametersGenerator gen =
        new PKCS5S2ParametersGenerator(DigestFactory.createSHA256());
    gen.init(password.toArrayUnsafe(), getSalt().toArrayUnsafe(), c);
    final int keySizeInBits = getDkLen() * 8;
    final byte[] key = ((KeyParameter) gen.generateDerivedParameters(keySizeInBits)).getKey();
    return Bytes.wrap(key);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("dklen", getDkLen())
        .add("c", c)
        .add("prf", prf)
        .add("salt", getSalt())
        .toString();
  }
}

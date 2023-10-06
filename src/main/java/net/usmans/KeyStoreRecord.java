package net.usmans;

import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.keystore.model.KeyStoreData;

public record KeyStoreRecord(KeyStoreData keyStoreData, Bytes privateKey, String password) {
}

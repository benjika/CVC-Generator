package org.hit.fintech2018.katz;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public interface CVCGenerator {

    public byte[] getCVCValue(byte[] data, byte[] key1, byte[] key2, int digits) throws NoSuchPaddingException, NoSuchAlgorithmException;

    public byte[] getCVCValue(byte[] pan, byte[] expiry, byte[] serviceCode, byte[] key1, byte[] key2, int digits);

    public boolean checkCVCValue(byte[] data, byte[] key1, byte[] key2, byte[] cvcValue);

}

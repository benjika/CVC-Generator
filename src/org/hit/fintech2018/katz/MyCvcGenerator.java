package org.hit.fintech2018.katz;

import static java.lang.System.arraycopy;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class MyCvcGenerator implements CVCGenerator {


    @Override
    public byte[] getCVCValue(byte[] data, byte[] key1, byte[] key2, int digits)
            throws NoSuchPaddingException, NoSuchAlgorithmException {

        if (data == null || key1 == null || key2 == null || digits == 0) {
            throw new NoSuchPaddingException();
        }

        if (data.length > 16 || key1.length != 8 || key2.length != 8 || digits > 16) {
            throw new NoSuchPaddingException();
        }

        //get data and pad if necessary
        data = padData(data);

        //split into two halves
        byte[] d1 = new byte[data.length / 2];
        arraycopy(data, 0, d1, 0, d1.length);
        byte[] d2 = new byte[data.length / 2];
        arraycopy(data, d1.length, d2, 0, d2.length);

        //encrypt d1 with key1. the result is t1
        byte[] t1 = encryptDes(key1, d1);

        //XOR  d2 and t1
        byte[] d2XORt1 = XorArrays(d2, t1);

        //create key for 3des
        byte[] key1key2key1 = mergeKeys(key1, key2);

        //encrypt XOR result with key1/key2/key1 (3des)
        byte[] t2 = encrypt3DES(key1key2key1, d2XORt1);

        //cast each byte to two bits
        byte[] result = arrangeUnderOverTenAndConcut(t2);

        //return first "digits" members
        return packArrBitToByte(Arrays.copyOfRange(result, 0, digits));
    }

    @Override
    public byte[] getCVCValue(byte[] pan, byte[] expiry, byte[] serviceCode, byte[] key1, byte[] key2, int digits) {

        byte[] data = new byte[pan.length + expiry.length + serviceCode.length];
        arraycopy(pan, 0, data, 0, pan.length);
        arraycopy(expiry, 0, data, pan.length, expiry.length);
        arraycopy(serviceCode, 0, data, pan.length + expiry.length, serviceCode.length);


        try {
            return getCVCValue(packArrBitToByte(data), key1, key2, digits);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean checkCVCValue(byte[] data, byte[] key1, byte[] key2, byte[] cvcValue) {

        if (cvcValue == null)
            return false;

        if (cvcValue.length == 0)
            return false;


        byte[] result;

        try {
            result = getCVCValue(data, key1, key2, cvcValue.length);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return Arrays.equals(cvcValue, result);
    }

    static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x ", b));
        return sb.toString();
    }

    private byte[] padData(byte[] data) {

        if (data.length < 16) {
            byte[] result = new byte[16];
            arraycopy(data, 0, result, 0, data.length);
            data = result;
        }

        return data;
    }

    private byte[] encryptDes(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException {


        if (data.length != 8 || key.length != 8) {
            throw new NoSuchPaddingException();
        }

        SecretKey secretKey1 = (SecretKey) new SecretKeySpec(key, "DES");
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey1);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            throw new NoSuchAlgorithmException();
        }
    }

    private byte[] XorArrays(byte[] arr1, byte[] arr2) throws NoSuchPaddingException {

        if (arr1.length != arr2.length) throw new NoSuchPaddingException();

        byte[] result = new byte[arr1.length];

        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (arr1[i] ^ arr2[i]);
        }

        return result;

    }

    private byte[] mergeKeys(byte[] key1, byte[] key2) throws NoSuchPaddingException {

        if (key1.length != 8 || key2.length != 8)
            throw new NoSuchPaddingException();

        byte[] result = new byte[key1.length * 3];

        for (int i = 0; i < key1.length; i++) {
            result[i] = key1[i];
            result[i + 2 * key1.length] = key1[i];
        }

        for (int i = key1.length, j = 0; j < key2.length; i++, j++) {
            result[i] = key2[j];
        }
        return result;
    }

    private byte[] encrypt3DES(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException {

        if (key.length != 24 || data.length != 8) {
            throw new NoSuchPaddingException();
        }

        SecretKey secretKey = (SecretKey) new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            throw new NoSuchAlgorithmException();
        }
    }

    private byte[] arrangeUnderOverTenAndConcut(byte[] arr) throws NoSuchPaddingException {

        if (arr == null) throw new NoSuchPaddingException();

        byte[] underTen = new byte[arr.length * 2];
        byte[] overTen = new byte[arr.length * 2];
        int underCount = 0, overCount = 0;
        for (byte b : arr) {

            byte left = (byte) ((b >> 4) & 0x0f);
            byte right = (byte) (b & 0x0f);

            if (left >= 0 && left < 10)
                underTen[underCount++] = left;
            else
                overTen[overCount++] = (byte) (0x0f & (left - 10));

            if (right >= 0 && right < 10)
                underTen[underCount++] = right;
            else
                overTen[overCount++] = (byte) (0x0f & (right - 10));
        }


        arraycopy(overTen, 0, underTen, underCount, overCount);


        return underTen;
    }

    private byte[] packArrBitToByte(byte[] arr) {

        byte[] result = new byte[arr.length / 2 + arr.length % 2];
        int i = 0;
        boolean even = true;

        for (byte b : arr) {
            if (even) result[i] = (byte) ((b & 0x0f) << 4);
            else result[i++] += (byte) (b % 0x0f);
            even = !even;
        }

        return result;
    }

    private byte[] unpackArrByteToBit(byte[] arr) {

        byte[] result = new byte[arr.length * 2];

        for (int i = 0, j = 0; j < result.length; i++, j += 2) {
            result[j] = (byte) ((arr[i] >> 4) & 0x0F);
            result[j + 1] = (byte) (arr[i] & 0x0F);
        }

        return result;
    }
}

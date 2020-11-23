package bab4;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

/**
 * Contoh RSA dasar.
 */
public class ContohRSADasar
{
    public static void main(String[] args) throws Exception
    {
        byte[]           masukan = new byte[] { (byte)0xde, (byte)0xba };
        Cipher           cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");

        //menciptakan kunci
        KeyFactory       pabrikKunci = KeyFactory.getInstance("RSA", "BC");

        RSAPublicKeySpec spekKunciPublik = new RSAPublicKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16));
                
        RSAPrivateKeySpec spekKunciPrivat = new RSAPrivateKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16));

        RSAPublicKey kunciPublik = (RSAPublicKey)pabrikKunci.generatePublic(spekKunciPublik);
        RSAPrivateKey kunciPrivat = (RSAPrivateKey)pabrikKunci.generatePrivate(
                                                                      spekKunciPrivat);

        System.out.println("masukan : " + Utils.toHex(masukan));

        //langkah enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunciPublik);

        byte[] cipherTeks = cipher.doFinal(masukan);

        System.out.println("cipher: " + Utils.toHex(cipherTeks));

        //langkah dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunciPrivat);

        byte[] plainTeks = cipher.doFinal(cipherTeks);

        System.out.println("plain : " + Utils.toHex(plainTeks));
    }
}
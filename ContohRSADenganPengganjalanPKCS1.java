package bab4;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Contoh RSA dengan pengganjalan PKCS #1.
 */
public class ContohRSADenganPengganjalanPKCS1
{
    public static void main(String[] args) throws Exception
    {
        byte[]           masukan = new byte[] { 0x00, (byte)0xbe, (byte)0xca };
        Cipher           cipher = Cipher.getInstance("RSA/None/PKCS1Padding","BC");

        SecureRandom     acak = Utils.ciptakanAcakTetap();

        //menciptakan kunci-kunci
        KeyPairGenerator pembangkit = KeyPairGenerator.getInstance("RSA", "BC");

        pembangkit.initialize(256, acak);

        KeyPair          sepasang = pembangkit.generateKeyPair();
        Key              kunciPublik = sepasang.getPublic();
        Key              kunciPrivat = sepasang.getPrivate();

        System.out.println("masukan : " + Utils.toHex(masukan));

        //langkah enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunciPublik, acak);

        byte[] cipherTeks = cipher.doFinal(masukan);

        System.out.println("cipher: " + Utils.toHex(cipherTeks));

        //langkah dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunciPrivat);

        byte[] plainTeks = cipher.doFinal(cipherTeks);

        System.out.println("plain : " + Utils.toHex(plainTeks));
    }
}


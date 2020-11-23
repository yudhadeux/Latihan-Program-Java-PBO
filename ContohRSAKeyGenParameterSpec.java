package bab4;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;

/**
 * Contoh RSA dasar.
 */
public class ContohRSAKeyGenParameterSpec
{
    public static void main(String[] args) throws Exception
    {
        byte[]           masukan = new byte[] { (byte)0xde, (byte)0xca };
        Cipher           cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");

        //menciptakan kunci
        KeyPairGenerator pabrikKunci = KeyPairGenerator.getInstance("RSA", "BC");
        SecureRandom     acak = Utils.ciptakanAcakTetap();
        
        pabrikKunci.initialize(
              new RSAKeyGenParameterSpec(256, RSAKeyGenParameterSpec.F4), acak);

        
        KeyPair              sepasang = pabrikKunci.generateKeyPair();
        RSAPublicKey      kunciPublik = (RSAPublicKey)sepasang.getPublic();
        RSAPrivateKey  kunciPrivat = (RSAPrivateKey)sepasang.getPrivate();
  
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
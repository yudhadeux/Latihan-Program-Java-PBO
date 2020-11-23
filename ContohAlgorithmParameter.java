package bab4;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

/**
 * Contoh El Gamal dengan pembangkitan kunci acak.
 */
public class ContohAlgorithmParameter
{
    public static void main(String[] args) throws Exception
    {
        byte[]           masukan = new byte[] { (byte)0xbe, (byte)0xca };
        Cipher           cipher = Cipher.getInstance(
                                             "ElGamal/None/NoPadding", "BC");
        SecureRandom     acak = Utils.ciptakanAcakTetap();

        //menciptakan parameter-parameter
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(
                                                                 "ElGamal", "BC");

        apg.init(256, acak);

        AlgorithmParameters     param2 = apg.generateParameters();
        AlgorithmParameterSpec  dhSpek = param2.getParameterSpec(
                                                            DHParameterSpec.class);

        //menciptakan kunci-kunci
        KeyPairGenerator pembangkit = KeyPairGenerator.getInstance("ElGamal", "BC");

        pembangkit.initialize(dhSpek, acak);

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


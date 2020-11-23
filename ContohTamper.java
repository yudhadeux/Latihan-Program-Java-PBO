package bab3;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * pesan dimodifikasi (oleh penyerang), enkripsi plain teks, AES dengan mode CTR
 */
public class ContohTamper
{
    public static void main(String[] args) throws Exception
    {
        SecureRandom    acak = new SecureRandom();
        IvParameterSpec ivSpec = Utils.CiptakanCtrIvUntukAES(1, acak);
        Key             kunci = Utils.ciptakanKunciUntukAES(256, acak);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          masukan = "Transfer 0000100 ke REK 1234-5678";

        System.out.println("masukan : " + masukan);

        //langkah enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        byte[] cipherTeks = cipher.doFinal(Utils.toByteArray(masukan));

        //langkah modifikasi (tampering)
        cipherTeks[9] ^= '0' ^ '9';

        //lengkah dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        byte[] plainTeks = cipher.doFinal(cipherTeks);

        System.out.println("plain : " + Utils.toString(plainTeks));
    }
}


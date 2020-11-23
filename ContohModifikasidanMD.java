package bab3;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Pesan dimodifikasi, enkripsi dengan MD, AES dengan mode CTR
 */
public class ContohModifikasidanMD
{
    public static void main(String[] args) throws Exception
    {
        SecureRandom    acak = new SecureRandom();
        IvParameterSpec ivSpec = Utils.CiptakanCtrIvUntukAES(1, acak);
        Key             kunci = Utils.ciptakanKunciUntukAES(256, acak);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          masukan = "Transfer 0000100 ke REK 1234-5678";
        MessageDigest   hash = MessageDigest.getInstance("SHA-1", "BC");

        System.out.println("masukan : " + masukan);

        //langkah enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        byte[] cipherTeks = new byte[cipher.getOutputSize(
                                       masukan.length() + hash.getDigestLength())];

        int ctPanjang = cipher.update(Utils.toByteArray(masukan), 0, masukan.length(),
                                                                   cipherTeks, 0);

        hash.update(Utils.toByteArray(masukan));

        ctPanjang += cipher.doFinal(hash.digest(), 0, hash.getDigestLength(),
                                                             cipherTeks, ctPanjang);

        //langkah modifikasi
        cipherTeks[9] ^= '0' ^ '9';

        //langkah dekripsi

        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        byte[] plainTeks = cipher.doFinal(cipherTeks, 0, ctPanjang);
        int    panjangPesan = plainTeks.length - hash.getDigestLength();

        hash.update(plainTeks, 0, panjangPesan);

        byte[] hashPesan = new byte[hash.getDigestLength()];
        System.arraycopy(plainTeks, panjangPesan, hashPesan,
                                                       0, hashPesan.length);

        System.out.println("plain : " + Utils.toString(plainTeks, panjangPesan)
             + " verifikasi: " + MessageDigest.isEqual(hash.digest(), hashPesan));
    }
}


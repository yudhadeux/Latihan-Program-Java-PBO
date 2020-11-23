package bab3;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pesan termodifikasi dengan HMAC, enkripsi dengan AES dengan mode CTR.
 */
public class ContohModifikasiDenganHMAC
{
    public static void main(String[] args) throws Exception
    {
        SecureRandom    acak = new SecureRandom();
        IvParameterSpec ivSpec = Utils.CiptakanCtrIvUntukAES(1, acak);
        Key             kunci = Utils.ciptakanKunciUntukAES(256, acak);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          masukan = "Transfer 0000100 ke REK 1234-5678";

        Mac             hMac = Mac.getInstance("HmacSHA1", "BC");
        Key             kunciHMAC = new SecretKeySpec(kunci.getEncoded(), "HmacSHA1");

        System.out.println("masukan : " + masukan);

        //langkah enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        byte[] cipherTeks = new byte[cipher.getOutputSize(
                                        masukan.length() + hMac.getMacLength())];

        int ctPanjang = cipher.update(Utils.toByteArray(masukan), 0, masukan.length(),
                                                                  cipherTeks, 0);

        hMac.init(kunciHMAC);
        hMac.update(Utils.toByteArray(masukan));

        ctPanjang += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(),
                                                            cipherTeks, ctPanjang);

        //langkah pemodifikasian (tampering)
        cipherTeks[9] ^= '0' ^ '9';

        //mengganti digest
        // ?

        //langkah dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        byte[] plainTeks = cipher.doFinal(cipherTeks, 0, ctPanjang);
        int    panjangPesan = plainTeks.length - hMac.getMacLength();

        hMac.init(kunciHMAC);
        hMac.update(plainTeks, 0, panjangPesan);

        byte[] hashPesan = new byte[hMac.getMacLength()];
        System.arraycopy(plainTeks, panjangPesan, hashPesan,
                                                         0, hashPesan.length);

        System.out.println("plain : " + Utils.toString(plainTeks, panjangPesan)
             + " verifikasi: " + MessageDigest.isEqual(hMac.doFinal(), hashPesan));
    }
}
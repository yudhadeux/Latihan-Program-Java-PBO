package bab3;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pesan tanpa modifikasi dengan MAC (DES), enkripsi AES dengan mode CTR
 */
public class ContohCipherMAC
{
    public static void main(String[] args) throws Exception
    {
        SecureRandom    acak = new SecureRandom();
        IvParameterSpec ivSpec = Utils.CiptakanCtrIvUntukAES(1, acak);
        Key             kunci = Utils.ciptakanKunciUntukAES(256, acak);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          masukan = "Transfer 0000100 ke REK 1234-5678";
        Mac             mac = Mac.getInstance("DES", "BC");
        byte[]          byteKunciMAC = new byte[] {
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        Key             kunciMAC = new SecretKeySpec(byteKunciMAC, "DES");

        System.out.println("masukan : " + masukan);

        //lengkah enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        byte[] cipherTeks = new byte[cipher.getOutputSize(
                                            masukan.length() + mac.getMacLength())];

        int ctLength = cipher.update(Utils.toByteArray(masukan), 0, masukan.length(),
                                                                   cipherTeks, 0);

        mac.init(kunciMAC);
        mac.update(Utils.toByteArray(masukan));

        ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(),
                                                            cipherTeks, ctLength);

        //langkah dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        byte[] plainTeks = cipher.doFinal(cipherTeks, 0, ctLength);
        int    panjangPesan = plainTeks.length - mac.getMacLength();

        mac.init(kunciMAC);
        mac.update(plainTeks, 0, panjangPesan);

        byte[] hashPesan = new byte[mac.getMacLength()];
        System.arraycopy(plainTeks, panjangPesan, hashPesan,
                                                           0, hashPesan.length);

        System.out.println("plain : " + Utils.toString(plainTeks, panjangPesan)
              + " verifikasi: " + MessageDigest.isEqual(mac.doFinal(), hashPesan));

    }
}


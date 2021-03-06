package bab2;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh enkripsi simetris sederhana dengan pengganjalan
 */
public class ContohPengganjalanSimetrisSederhana
{
    public static void main(String[] args) throws Exception
    {
        byte[] masukan = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
                          
        byte[] byteKunci = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

        SecretKeySpec kunci = new SecretKeySpec(byteKunci, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

        System.out.println("masukan : " + Utils.toHex(masukan));

        //enkripsi

        cipher.init(Cipher.ENCRYPT_MODE, kunci);

        byte[] cipherTeks = new byte[cipher.getOutputSize(masukan.length)];

        int pjgCipherTeks = cipher.update(masukan, 0, masukan.length, cipherTeks, 0);

        pjgCipherTeks += cipher.doFinal(cipherTeks, pjgCipherTeks);

        System.out.println("cipher: " + Utils.toHex(cipherTeks)
                                                + " byte: " + pjgCipherTeks);

        //dekripsi

        cipher.init(Cipher.DECRYPT_MODE, kunci);

        byte[] plainTeks = new byte[cipher.getOutputSize(pjgCipherTeks)];

        int pjgPlainTeks = cipher.update(cipherTeks, 0, pjgCipherTeks, plainTeks, 0);

        pjgPlainTeks += cipher.doFinal(plainTeks, pjgPlainTeks);

        System.out.println("plain : " + Utils.toHex(plainTeks)
                                                + " byte: " + pjgPlainTeks);
    }
}


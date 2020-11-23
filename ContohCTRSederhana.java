package bab2;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh enkripsi sederhana dengan CTR dan DES
 */
public class ContohCTRSederhana
{
    public static void main(String[] args) throws Exception
    {
        byte[] masukan = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
                                
        byte[] byteKunci = new byte[] {
                                0x01, 0x23, 0x45, 0x67,
                                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
                                
        byte[] byteIV = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01 };

        SecretKeySpec   kunci = new SecretKeySpec(byteKunci, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(byteIV);
        Cipher          cipher = Cipher.getInstance("DES/CTR/NoPadding", "BC");

        System.out.println("masukan : " + Utils.toHex(masukan));

        //enkripsi

        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        byte[] cipherTeks = new byte[cipher.getOutputSize(masukan.length)];

        int pjgCipherTeks = cipher.update(masukan, 0, masukan.length, cipherTeks, 0);

        pjgCipherTeks += cipher.doFinal(cipherTeks, pjgCipherTeks);

        System.out.println("cipher: " + Utils.toHex(cipherTeks, pjgCipherTeks)
                                                + " byte: " + pjgCipherTeks);

        //dekripsi

        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        byte[] plainTeks = new byte[cipher.getOutputSize(pjgCipherTeks)];

        int pjgPlainTeks = cipher.update(cipherTeks, 0, pjgCipherTeks, plainTeks, 0);

        pjgPlainTeks += cipher.doFinal(plainTeks, pjgPlainTeks);

        System.out.println("plain : " + Utils.toHex(plainTeks, pjgPlainTeks)
                                                + " byte: " + pjgPlainTeks);
    }
}


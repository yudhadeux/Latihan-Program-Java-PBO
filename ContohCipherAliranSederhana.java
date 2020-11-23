package bab2;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh cipher aliran dasar
 */
 
public class ContohCipherAliranSederhana
{
    public static void main(
        String[] args)
        throws Exception
    {
        byte[] masukan = new byte[] {
                          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                          (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff };
                          
        byte[] byteKunci = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

        SecretKeySpec kunci = new SecretKeySpec(byteKunci, "ARC4");

        Cipher        cipher = Cipher.getInstance("ARC4", "BC");

        System.out.println("masukan text : " + Utils.toHex(masukan));

        //enkripsi
        byte[] cipherTeks = new byte[masukan.length];

        cipher.init(Cipher.ENCRYPT_MODE, kunci);

        int pjgCipherTeks = cipher.update(masukan, 0, masukan.length, cipherTeks, 0);

        pjgCipherTeks += cipher.doFinal(cipherTeks, pjgCipherTeks);

        System.out.println("cipher teks: " + Utils.toHex(cipherTeks)
                                                     + " byte: " + pjgCipherTeks);

        //dekripsi
        byte[] plainTeks = new byte[pjgCipherTeks];

        cipher.init(Cipher.DECRYPT_MODE, kunci);

        int pjgPlainTeks = cipher.update(cipherTeks, 0, pjgCipherTeks, plainTeks, 0);

        pjgPlainTeks += cipher.doFinal(plainTeks, pjgPlainTeks);

        System.out.println("plain teks : " + Utils.toHex(plainTeks)
                                                     + " byte: " + pjgPlainTeks);
    }
}


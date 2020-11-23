package bab2;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CBC menggunakan DES dengan sebuah IV berbasis nonce. Pada kasus ini,
 * diberikan nomor pesan.
 */
public class ContohCBCNonceIvCBC
{
    public static void main(String[] args) throws Exception
    {
        byte[] masukan = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
                          
        byte[] byteKunci = new byte[] {
                          0x01, 0x23, 0x45, 0x67,
                          (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
                          
        byte[] nomorPesan = new byte[] {
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        IvParameterSpec ivNol = new IvParameterSpec(new byte[8]);

        SecretKeySpec   kunci = new SecretKeySpec(byteKunci, "DES");

        Cipher          cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");


        System.out.println("masukan : " + Utils.toHex(masukan));

        //enkripsi
        //menghasilkan IV
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivNol);

        IvParameterSpec ivEnkripsi = new IvParameterSpec(
                                               cipher.doFinal(nomorPesan), 0, 8);

        //mengenkripsi pesan
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivEnkripsi);

        byte[] cipherTeks = new byte[cipher.getOutputSize(masukan.length)];

        int pjgCipherTeks = cipher.update(masukan, 0, masukan.length, cipherTeks, 0);

        pjgCipherTeks += cipher.doFinal(cipherTeks, pjgCipherTeks);

        System.out.println("cipher: " + Utils.toHex(cipherTeks, pjgCipherTeks)
                                                + " byte: " + pjgCipherTeks);

        //dekripsi
        //menghasilkan IV
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivNol);

        IvParameterSpec ivDekripsi = new IvParameterSpec(
                                               cipher.doFinal(nomorPesan), 0, 8);

        //mendekripsi pesan
        cipher.init(Cipher.DECRYPT_MODE, kunci, ivDekripsi);

        byte[] plainTeks = new byte[cipher.getOutputSize(pjgCipherTeks)];

        int pjgPlainTeks = cipher.update(cipherTeks, 0, pjgCipherTeks, plainTeks, 0);

        pjgPlainTeks += cipher.doFinal(plainTeks, pjgPlainTeks);

        System.out.println("plain : " + Utils.toHex(plainTeks, pjgPlainTeks)
                                                + " byte: " + pjgPlainTeks);
    }
}


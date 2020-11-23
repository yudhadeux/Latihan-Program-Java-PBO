package bab2;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh dasar menggunakan kelas KeyGenerator dan
 * menunjukkan bagaimana menciptakan sebuah SecretKeySpec dari kunci terenkode.
 */
public class ContohPembangkitanKunci
{
    public static void main(String[] args) throws Exception
    {
        byte[] masukan = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
                            
        byte[] byteIV = new byte[] {
                            0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        KeyGenerator    pembangkit = KeyGenerator.getInstance("AES", "BC");

        pembangkit.init(192);

        Key kunciEnkripsi = pembangkit.generateKey();

        System.out.println("kunci : " + Utils.toHex(kunciEnkripsi.getEncoded()));

        System.out.println("masukan : " + Utils.toHex(masukan));

        //enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunciEnkripsi,
                                               new IvParameterSpec(byteIV));

        byte[] cipherTeks = new byte[cipher.getOutputSize(masukan.length)];

        int pjgCipherTeks = cipher.update(masukan, 0, masukan.length, cipherTeks, 0);

        pjgCipherTeks += cipher.doFinal(cipherTeks, pjgCipherTeks);

        //menciptakan kunci dekripsi menggunakan informasi yang
        //diekstrak dari kunci enkripsi

        Key    kunciDekripsi = new SecretKeySpec(
                        kunciEnkripsi.getEncoded(), kunciEnkripsi.getAlgorithm());

        cipher.init(Cipher.DECRYPT_MODE, kunciDekripsi,
                                               new IvParameterSpec(byteIV));

        byte[] plainTeks = new byte[cipher.getOutputSize(pjgCipherTeks)];

        int pjgPlainTeks = cipher.update(cipherTeks, 0, pjgCipherTeks, plainTeks, 0);

        pjgPlainTeks += cipher.doFinal(plainTeks, pjgPlainTeks);

        System.out.println("plain teks : " + Utils.toHex(plainTeks, pjgPlainTeks)
                                                + " byte: " + pjgPlainTeks);
    }
}

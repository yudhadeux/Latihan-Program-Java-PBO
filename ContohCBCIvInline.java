package bab2;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh enkripsi simetris dengan pengganjalan dan CBC menggunakan DES
 * dengan vektor inisialisasi.
 */
public class ContohCBCIvInline
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
                            
        byte[] byteIV = new byte[] {
                            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

        SecretKeySpec   kunci = new SecretKeySpec(byteKunci, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        Cipher          cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");

        System.out.println("masukan : " + Utils.toHex(masukan));

        //enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        byte[] cipherTeks = new byte[
                           cipher.getOutputSize(byteIV.length + masukan.length)];

        int pjgCipherTeks = cipher.update(byteIV, 0, byteIV.length, cipherTeks, 0);

        pjgCipherTeks += cipher.update(masukan, 0, masukan.length, cipherTeks, pjgCipherTeks);

        pjgCipherTeks += cipher.doFinal(cipherTeks, pjgCipherTeks);

        System.out.println("cipher: " + Utils.toHex(cipherTeks, pjgCipherTeks)
                                                + " byte: " + pjgCipherTeks);

        //dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        byte[] buf = new byte[cipher.getOutputSize(pjgCipherTeks)];

        int pjgBuff = cipher.update(cipherTeks, 0, pjgCipherTeks, buf, 0);

        pjgBuff += cipher.doFinal(buf, pjgBuff);

        //menghapus iv dari awal pesan
        byte[] plainTeks = new byte[pjgBuff - byteIV.length];

        System.arraycopy(buf, byteIV.length, plainTeks, 0, plainTeks.length);

        System.out.println("plain : " + Utils.toHex(plainTeks, plainTeks.length)
                                                + " byte: " + plainTeks.length);
    }
}


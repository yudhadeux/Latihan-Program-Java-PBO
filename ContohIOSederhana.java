package bab2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh IO dasar dengan CTR menggunakan AES
 */
public class ContohIOSederhana
{
    public static void main(
        String[] args)
        throws Exception
    {
        byte[]          masukan = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
                            
        byte[]          byteKunci = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

        byte[]          byteIV = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

        SecretKeySpec   kunci = new SecretKeySpec(byteKunci, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(byteIV);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");


        System.out.println("masukan : " + Utils.toHex(masukan));

        //enkripsi
        cipher.init(Cipher.ENCRYPT_MODE, kunci, ivSpec);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(masukan);
        CipherInputStream       cIn = new CipherInputStream(bIn, cipher);
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = cIn.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] cipherTeks = bOut.toByteArray();

        System.out.println("cipher: " + Utils.toHex(cipherTeks));

        //dekripsi
        cipher.init(Cipher.DECRYPT_MODE, kunci, ivSpec);

        bOut = new ByteArrayOutputStream();

        CipherOutputStream      cOut = new CipherOutputStream(bOut, cipher);

        cOut.write(cipherTeks);

        cOut.close();

        System.out.println("plain: " + Utils.toHex(bOut.toByteArray()));
    }
}


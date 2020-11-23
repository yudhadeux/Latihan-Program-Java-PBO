package bab3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;

/**
 * Contoh IO dasar menggunakan SHA1
 */
public class ContohIODigest
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]          masukan = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };;

        MessageDigest   hash = MessageDigest.getInstance("SHA1");
        System.out.println("masukan     : " + Utils.toHex(masukan));

        //masukan
        ByteArrayInputStream  bIn = new ByteArrayInputStream(masukan);
        DigestInputStream     dIn = new DigestInputStream(bIn, hash);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int     ch;
        while ((ch = dIn.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] masukanBaru = bOut.toByteArray();

        System.out.println("Digest masukan : "
                                + Utils.toHex(dIn.getMessageDigest().digest()));

        //keluaran
        bOut = new ByteArrayOutputStream();

        DigestOutputStream      dOut = new DigestOutputStream(bOut, hash);

        dOut.write(masukanBaru);

        dOut.close();

        System.out.println("Digest keluaran: "
                              + Utils.toHex(dOut.getMessageDigest().digest()));
    }
}
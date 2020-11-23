package bab4;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Contoh penukaran kunci RSA.
 */
public class ContohPenukaranKunciRSA
{
    private static byte[] paketKunciDanIV(
        Key          kunci,
        IvParameterSpec ivSpek)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        bOut.write(ivSpek.getIV());
        bOut.write(kunci.getEncoded());

        return bOut.toByteArray();
    }

    private static Object[] bukaPaketKunciDanIV(
        byte[]    data)
    {
        byte[]    kunciD = new byte[16];
        byte[]    iv = new byte[data.length - 16];

        return new Object[] {
             new SecretKeySpec(data, 16, data.length - 16, "AES"),
             new IvParameterSpec(data, 0, 16)
        };
    }

    public static void main(String[] args) throws Exception
    {
        byte[]           masukan = new byte[] { 0x00, (byte)0xbe, (byte)0xca };
        SecureRandom     acak = Utils.ciptakanAcakTetap();

        //menciptakan kunci RSA
        KeyPairGenerator pembangkit = KeyPairGenerator.getInstance("RSA", "BC");

        pembangkit.initialize(1024, acak);

        KeyPair          sepasang = pembangkit.generateKeyPair();
        Key              kunciPublik = sepasang.getPublic();
        Key              kunciPrivat = sepasang.getPrivate();

        System.out.println("masukan            : " + Utils.toHex(masukan));

        //menciptakan kunci simetris dan IV
        Key             sKunci = Utils.ciptakanKunciUntukAES(256, acak);
        IvParameterSpec sIvSpek = Utils.CiptakanCtrIvUntukAES(0, acak);

        //langkah pembungkusan kunci simetris/IV
        Cipher           xCipher = Cipher.getInstance(
                                   "RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");

        xCipher.init(Cipher.ENCRYPT_MODE, kunciPublik, acak);

        byte[]          blokKunci = xCipher.doFinal(paketKunciDanIV(sKunci, sIvSpek));

        //langkah enkripsi
        Cipher          sCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        sCipher.init(Cipher.ENCRYPT_MODE, sKunci, sIvSpek);

        byte[] cipherTeks = sCipher.doFinal(masukan);

        System.out.println("Panjang blokKunci  : " + blokKunci.length);
        System.out.println("Panjang cipherTeks: " + cipherTeks.length);

        //langkah membuka bungkusan kunci simetris/IV
        xCipher.init(Cipher.DECRYPT_MODE, kunciPrivat);

        Object[] kunciIV = bukaPaketKunciDanIV(xCipher.doFinal(blokKunci));

        //langkah dekripsi
        sCipher.init(Cipher.DECRYPT_MODE, (Key)kunciIV[0],
                                              (IvParameterSpec)kunciIV[1]);

        byte[] plainTeks = sCipher.doFinal(cipherTeks);

        System.out.println("plain            : " + Utils.toHex(plainTeks));    }
}
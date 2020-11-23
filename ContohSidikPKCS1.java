package bab4;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

public class ContohSidikPKCS1
{
    public static void main(String[] args) throws Exception
    {
        KeyPairGenerator kunciBangkit = KeyPairGenerator.getInstance("RSA", "BC");

        kunciBangkit.initialize(512, new SecureRandom());

        KeyPair           pasanganKunci = kunciBangkit.generateKeyPair();
        Signature         sidik = Signature.getInstance("SHA1withRSA", "BC");

        //menghasilkan sebuah sidik
        sidik.initSign(pasanganKunci.getPrivate(), Utils.ciptakanAcakTetap());

        byte[] pesan = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sidik.update(pesan);

        byte[] byteSidik = sidik.sign();

        //verifikasi sidik
        sidik.initVerify(pasanganKunci.getPublic());

        sidik.update(pesan);

        if (sidik.verify(byteSidik))
        {
            System.out.println("verifikasi sidik berhasil.");
        }
        else
        {
            System.out.println("verifikasi sidik gagal.");
        }
    }
}


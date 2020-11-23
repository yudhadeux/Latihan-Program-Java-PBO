package bab4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class ContohDiffieHellmanDasar
{
    private static BigInteger g512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
          + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
          + "410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
          + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
          + "f0573bf047a3aca98cdf3b", 16);

    public static void main(String[] args) throws Exception
    {
        DHParameterSpec parameterDH = new DHParameterSpec(p512, g512);
        KeyPairGenerator bangkitKunci = KeyPairGenerator.getInstance("DH", "BC");

        bangkitKunci.initialize(parameterDH, Utils.ciptakanAcakTetap());

        //pengaturan
        KeyAgreement aKunciPerjanjian = KeyAgreement.getInstance("DH", "BC");
        KeyPair      aSepasang = bangkitKunci.generateKeyPair();
        KeyAgreement bKunciPerjanjian = KeyAgreement.getInstance("DH", "BC");
        KeyPair      bSepasang = bangkitKunci.generateKeyPair();

        //perjanjian dua pihak
        aKunciPerjanjian.init(aSepasang.getPrivate());
        bKunciPerjanjian.init(bSepasang.getPrivate());

        aKunciPerjanjian.doPhase(bSepasang.getPublic(), true);
        bKunciPerjanjian.doPhase(aSepasang.getPublic(), true);

        //membangkitkan byte-byte kunci
        MessageDigest    hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aBersama = hash.digest(aKunciPerjanjian.generateSecret());
        byte[] bBersama = hash.digest(bKunciPerjanjian.generateSecret());

        System.out.println(Utils.toHex(aBersama));
        System.out.println(Utils.toHex(bBersama));
    }
}


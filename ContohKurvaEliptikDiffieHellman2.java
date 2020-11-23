package bab4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

public class ContohKurvaEliptikDiffieHellman2
{
    public static void main(String[] args) throws Exception
    {
        KeyPairGenerator bangkitKunci = KeyPairGenerator.getInstance("ECDH", "BC");
        ECGenParameterSpec kurvaEliptikSpek = new ECGenParameterSpec("prime192v1");

        bangkitKunci.initialize(kurvaEliptikSpek, Utils.ciptakanAcakTetap());

        //pengaturan
        KeyAgreement aKunciPerjanjian = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      aSepasang = bangkitKunci.generateKeyPair();
        KeyAgreement bKunciPerjanjian = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      bSepasang = bangkitKunci.generateKeyPair();


        //perjanjian dua pihak
        aKunciPerjanjian.init(aSepasang.getPrivate());
        bKunciPerjanjian.init(bSepasang.getPrivate());

        aKunciPerjanjian.doPhase(bSepasang.getPublic(), true);
        bKunciPerjanjian.doPhase(aSepasang.getPublic(), true);

        //menghasilkan byte-byte kunci
        MessageDigest    hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aBersama = hash.digest(aKunciPerjanjian.generateSecret());
        byte[] bBersama = hash.digest(bKunciPerjanjian.generateSecret());

        System.out.println(Utils.toHex(aBersama));
        System.out.println(Utils.toHex(bBersama));
    }
}
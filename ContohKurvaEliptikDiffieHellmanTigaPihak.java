package bab4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.Key;

import javax.crypto.KeyAgreement;

public class ContohKurvaEliptikDiffieHellmanTigaPihak
{
    public static void main(String[] args) throws Exception
    {
        KeyPairGenerator bangkitKunci = KeyPairGenerator.getInstance("ECDH", "BC");

        EllipticCurve kurva = new EllipticCurve(
           new ECFieldFp(new BigInteger(
                         "fffffffffffffffffffffffffffffffeffffffffffffffff", 16)),
           new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
           new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16));

        ECParameterSpec kurvaEliptikSpek = new ECParameterSpec(
          kurva,
          new ECPoint(
           new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
           new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee", 16)),
          new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
          1);

        bangkitKunci.initialize(kurvaEliptikSpek, Utils.ciptakanAcakTetap());

        //pengaturan
        KeyAgreement aKunciPerjanjian = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      aSepasang = bangkitKunci.generateKeyPair();
        
        KeyAgreement bKunciPerjanjian = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      bSepasang = bangkitKunci.generateKeyPair();
        
        KeyAgreement cKunciPerjanjian = KeyAgreement.getInstance("DH", "BC");
        KeyPair      cSepasang = bangkitKunci.generateKeyPair();

        //perjanjian dua pihak
        aKunciPerjanjian.init(aSepasang.getPrivate());
        bKunciPerjanjian.init(bSepasang.getPrivate());
        cKunciPerjanjian.init(cSepasang.getPrivate());
        
        Key ac = aKunciPerjanjian.doPhase(cSepasang.getPublic(), false);
        Key ba = bKunciPerjanjian.doPhase(aSepasang.getPublic(), false);
        Key cb = cKunciPerjanjian.doPhase(bSepasang.getPublic(), false);

        aKunciPerjanjian.doPhase(cb, true);
        bKunciPerjanjian.doPhase(ac, true);
        cKunciPerjanjian.doPhase(ba, true);

        //menghasilkan byte-byte kunci
        MessageDigest    hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aBersama = hash.digest(aKunciPerjanjian.generateSecret());
        byte[] bBersama = hash.digest(bKunciPerjanjian.generateSecret());
        byte[] cBersama = hash.digest(cKunciPerjanjian.generateSecret());

        System.out.println(Utils.toHex(aBersama));
        System.out.println(Utils.toHex(bBersama));
        System.out.println(Utils.toHex(cBersama));
    }
}
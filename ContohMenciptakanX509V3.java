package bab6;

import java.math.BigInteger;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

   /**
   * Penciptaan sertifikat X.509 V3 dengan TLS flagging.
   */
  public class ContohMenciptakanX509V3
  {
    public static X509Certificate generateV3Certificate(KeyPair sepasang)
       throws InvalidKeyException, NoSuchProviderException, SignatureException
    {
       //menghasilkan sertifikat
       X509V3CertificateGenerator sertPembangkit = new X509V3CertificateGenerator();

       sertPembangkit.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
       sertPembangkit.setIssuerDN(new X500Principal("CN=Sertifikat Test"));
       sertPembangkit.setNotBefore(new Date(System.currentTimeMillis() - 50000));
       sertPembangkit.setNotAfter(new Date(System.currentTimeMillis() + 50000));
       sertPembangkit.setSubjectDN(new X500Principal("CN=Sertifikat Test"));
       sertPembangkit.setPublicKey(sepasang.getPublic());
       sertPembangkit.setSignatureAlgorithm("SHA256WithRSAEncryption");

       sertPembangkit.addExtension(X509Extensions.BasicConstraints, true,
                                                  new BasicConstraints(false));
       sertPembangkit.addExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
       sertPembangkit.addExtension(X509Extensions.ExtendedKeyUsage, true,
                            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

       sertPembangkit.addExtension(X509Extensions.SubjectAlternativeName, false,
                new GeneralNames(
                    new GeneralName(GeneralName.rfc822Name, "test@test.test")));

       return sertPembangkit.generateX509Certificate(sepasang.getPrivate(), "BC");
   }
   public static void main(String[] args) throws Exception
   {
     //menciptakan kunci-kunci
     KeyPair        sepasang = Utils.bangkitkanSepasangKunciRSA();

    //menghasilkan sertifikat
    X509Certificate sertifikat = generateV3Certificate(sepasang);

    //menunjukkan validasi dasar
    sertifikat.checkValidity(new Date());

    sertifikat.verify(sertifikat.getPublicKey());

    System.out.println("Sertifikat valid dibangkitkan");
  }
}


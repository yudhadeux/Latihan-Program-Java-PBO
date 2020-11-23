package bab6;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V1CertificateGenerator;
/**
 * Penciptakan sertifikat X.509 V1.
 */
public class ContohMenciptakanX509V1
{
   public static X509Certificate generateV1Certificate(KeyPair sepasang)
      throws InvalidKeyException, NoSuchProviderException, SignatureException
   {
      //membangkitkan sertifikat
      X509V1CertificateGenerator sertifikatBangkit = new X509V1CertificateGenerator();

      sertifikatBangkit.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
      sertifikatBangkit.setIssuerDN(new X500Principal("CN=Sertifikat Test"));
      sertifikatBangkit.setNotBefore(new Date(System.currentTimeMillis() - 50000));
      sertifikatBangkit.setNotAfter(new Date(System.currentTimeMillis() + 50000));
      sertifikatBangkit.setSubjectDN(new X500Principal("CN=Sertifikat Test"));
      sertifikatBangkit.setPublicKey(sepasang.getPublic());
      sertifikatBangkit.setSignatureAlgorithm("SHA256WithRSAEncryption");

      return sertifikatBangkit.generateX509Certificate(sepasang.getPrivate(), "BC");
   }

   public static void main(String[] args) throws Exception
   {
      //menciptakan kunci-kunci
      KeyPair         sepasang = Utils.bangkitkanSepasangKunciRSA();

      //membangkitkan sertifikat
      X509Certificate sert = generateV1Certificate(sepasang);

      //menunjukkan validasi dasar
      sert.checkValidity(new Date());

      sert.verify(sert.getPublicKey());

      System.out.println("Sertifikat valid dihasilkan");
   }
}
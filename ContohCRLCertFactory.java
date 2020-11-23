package bab7;

import java.io.ByteArrayInputStream;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

/**
 * Membaca sebuah CRL dengan CertificateFactory
 */
public class ContohCRLCertFactory
{
   public static void main(String[] args) throws Exception
   {
      //menciptakan kunci-kunci CA dan sertifikasi
      KeyPair         caSepasang = Utils.bangkitkanSepasangKunciRSA();
      X509Certificate caSert = Utils.hasilkanSertifikatAkar(caSepasang);
      BigInteger      nomorSeriRevokasi = BigInteger.valueOf(2);

      //menciptakan sebuah CRL yang merevokasi nomor sertifikat 2
      X509CRL         crl = ContohX509CRL.ciptakanCRL(
                         caSert, caSepasang.getPrivate(), nomorSeriRevokasi);


      //mengenkodenya dan merekonstruksinya
      ByteArrayInputStream bIn = new ByteArrayInputStream(crl.getEncoded());
      CertificateFactory   faktori = CertificateFactory.getInstance("X.509", "BC");

      crl = (X509CRL)faktori.generateCRL(bIn);

      //memverifikasi CRL
      crl.verify(caSert.getPublicKey(), "BC");

      //memeriksa apakah CRL merevokasi nomor sertifikat 2
      X509CRLEntry entry = crl.getRevokedCertificate(nomorSeriRevokasi);
      System.out.println("Detil Revokasi:");
      System.out.println("Nomor Sertifikat: " + entry.getSerialNumber());
      System.out.println("Issuer          : " +crl.getIssuerX500Principal());
    }
}
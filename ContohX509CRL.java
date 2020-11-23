package bab7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.*;

/**
 * Contoh dasar dari pembangkitan dan penggunaaan sebuah CRL.
 */
public class ContohX509CRL
{
   public static X509CRL ciptakanCRL(
      X509Certificate caSert,
      PrivateKey      caKunci,
      BigInteger      nomorSeriRevokasi)
      throws Exception
   {
      X509V2CRLGenerator  hasilCRL = new X509V2CRLGenerator();
      Date                skrg = new Date();

      hasilCRL.setIssuerDN(caSert.getSubjectX500Principal());

      hasilCRL.setThisUpdate(skrg);
      hasilCRL.setNextUpdate(new Date(skrg.getTime() + 100000));
      hasilCRL.setSignatureAlgorithm("SHA256WithRSAEncryption");

      hasilCRL.addCRLEntry(nomorSeriRevokasi, skrg, CRLReason.privilegeWithdrawn);

      hasilCRL.addExtension(X509Extensions.AuthorityKeyIdentifier,
                              false, new AuthorityKeyIdentifierStructure(caSert));
      hasilCRL.addExtension(X509Extensions.CRLNumber,
                                  false, new CRLNumber(BigInteger.valueOf(1)));

      return hasilCRL.generateX509CRL(caKunci, "BC");
   }
   public static void main(String[] args)
      throws Exception
   {
      //menciptakan kunci-kunci CA dan sertifikat
      KeyPair         caSepasang = Utils.bangkitkanSepasangKunciRSA();
      X509Certificate caSert = Utils.hasilkanSertifikatAkar(caSepasang);
      BigInteger      nomorSeriRevokasi = BigInteger.valueOf(2);

      //menciptakan sebuah CRL yang merevokasi nomor sertifikat 2
      X509CRL crl = ciptakanCRL(caSert, caSepasang.getPrivate(), nomorSeriRevokasi);

      //memverifikasi CRL
      crl.verify(caSert.getPublicKey(), "BC");

      //memeriksa apakah CRL merevokasi nomor sertifikat 2
      X509CRLEntry entri = crl.getRevokedCertificate(nomorSeriRevokasi);
      System.out.println("Detil Revokasi:");
      System.out.println("Nomor Sertifikat: " + entri.getSerialNumber());
      System.out.println("Issuer          : " +crl.getIssuerX500Principal());

      if (entri.hasExtensions())
      {

         byte[] ekstensi = entri.getExtensionValue(
                               X509Extensions.ReasonCode.getId());

         if (ekstensi != null)
         {
             ASN1Enumerated     kodeAlasan =
                       (ASN1Enumerated)X509ExtensionUtil.fromExtensionValue(ekstensi);

             System.out.println("Kode Alasan      : "+kodeAlasan.getValue());
         }
      }
   }
}
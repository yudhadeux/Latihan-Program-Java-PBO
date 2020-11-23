package bab7;

import java.math.BigInteger;
import java.security.KeyPair;

import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

import java.security.cert.X509CRLSelector;

import java.security.cert.X509Certificate;

import java.util.*;


/**
 * Menggunakan kelas X509CRLSelector dan kelas CertStore.
 */
public class ContohCRLCertStore
{
   public static void main(String[] args)
      throws Exception
   {
      //menciptakan kunci-kunci CA dan sertifikat
      KeyPair          caSepasang = Utils.bangkitkanSepasangKunciRSA();
      X509Certificate  caSert = Utils.hasilkanSertifikatAkar(caSepasang);
      BigInteger       nomorSeriRevokasi = BigInteger.valueOf(2);

      //menciptakan CRL yang merevokasi nomor sertifikat 2
      X509CRL       crl = ContohX509CRL.ciptakanCRL(
                                caSert, caSepasang.getPrivate(), nomorSeriRevokasi);


      //menempatkan CRL ke sebuah CertStore
      CollectionCertStoreParameters params = new CollectionCertStoreParameters(
                                                    Collections.singleton(crl));
      CertStore                     store = CertStore.getInstance(
                                                   "Collection", params, "BC");
      X509CRLSelector               selektor = new X509CRLSelector();

      selektor.addIssuerName(caSert.getSubjectX500Principal().getEncoded());

      Iterator                      it = store.getCRLs(selektor).iterator();

      while (it.hasNext())
      {
         crl = (X509CRL)it.next();

         //memverifikasi CRL
         crl.verify(caSert.getPublicKey(), "BC");

         //memeriksa apakah CRL merevokasi nomor sertifikat 2
         X509CRLEntry entri = crl.getRevokedCertificate(nomorSeriRevokasi);
         System.out.println("Detil Revokasi:");
         System.out.println("Nomor Sertifikat: " + entri.getSerialNumber());
         System.out.println("Issuer          : " +
                                                  crl.getIssuerX500Principal());
      }
    }
}
package bab6;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Contoh dasar pembacaan sertifikat jamak dengan sebuah CertificateFactory.
 */
public class ContohMultipleCertificate
{
   public static void main(String[] args) throws Exception
   {
     //menghasilkan kunci-kunci
     KeyPair         sepasang = Utils.bangkitkanSepasangKunciRSA();

     //menciptakan aliran masukan
     ByteArrayOutputStream bOut = new ByteArrayOutputStream();

     bOut.write(ContohMenciptakanX509V1.generateV1Certificate(sepasang).getEncoded());
     bOut.write(ContohMenciptakanX509V3.generateV3Certificate(sepasang).getEncoded());

     bOut.close();

     InputStream in = new ByteArrayInputStream(bOut.toByteArray());

     //menciptakan pabrik sertifikat
     CertificateFactory pabrik = CertificateFactory.getInstance("X.509","BC");

     //membaca sertifikat
     X509Certificate   sertX509;
     Collection        koleksi = new ArrayList();

     while((sertX509 = (X509Certificate)pabrik.generateCertificate(in)) != null)
     {
        koleksi.add(sertX509);
     }

     Iterator it = koleksi.iterator();
     while (it.hasNext())
     {
        System.out.println("versi: " +
                                  ((X509Certificate)it.next()).getVersion());
     }
  }
}


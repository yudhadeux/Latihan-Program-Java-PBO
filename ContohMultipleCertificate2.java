package bab6;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.openssl.PEMWriter;

/**
 * Contoh dasar pembacaan sertifikat jamak dengan sebuah CertificateFactory.
 */
public class ContohMultipleCertificate2
{
   public static void main(String[] args) throws Exception
   {
     //menghasilkan kunci-kunci
     KeyPair         sepasang = Utils.bangkitkanSepasangKunciRSA();

     //menciptakan aliran masukan
     ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    
     PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(bOut));

     pemWrt.writeObject(ContohMenciptakanX509V1.generateV1Certificate(sepasang));
     pemWrt.writeObject(ContohMenciptakanX509V3.generateV3Certificate(sepasang));
     
     pemWrt.close();

     bOut.close();
     
     System.out.println(Utils.toString(bOut.toByteArray()));

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


package bab6;

  import java.io.*;
  import java.security.*;
  import java.security.cert.CertificateFactory;
  import java.security.cert.X509Certificate;
  
  import org.bouncycastle.openssl.PEMWriter;

  /**
   * Contoh dasar penggunaan sebuah CertificateFactory.
   */
  public class ContohCertificateFactory2
  {
     public static void main(String[] args) throws Exception
     {
       //menciptakan kunci-kunci
       KeyPair         sepasang = Utils.bangkitkanSepasangKunciRSA();;

       //menciptakan aliran masukan
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();

       PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(bOut));

       pemWrt.writeObject(ContohMenciptakanX509V1.generateV1Certificate(sepasang));

       pemWrt.close();

       bOut.close();
       
       System.out.println(Utils.toString(bOut.toByteArray()));

       InputStream in = new ByteArrayInputStream(bOut.toByteArray());

      //menciptakan pabrik sertifikat
      CertificateFactory pabrik = CertificateFactory.getInstance("X.509","BC");

      //membaca sertifikat
      X509Certificate x509Cert = (X509Certificate)pabrik.generateCertificate(in);

      System.out.println("Issuer: " + x509Cert.getIssuerX500Principal());
  }
}

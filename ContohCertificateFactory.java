package bab6;

  import java.io.*;
  import java.security.*;
  import java.security.cert.CertificateFactory;
  import java.security.cert.X509Certificate;

  /**
   * Contoh dasar penggunaan sebuah CertificateFactory.
   */
  public class ContohCertificateFactory
  {
     public static void main(String[] args) throws Exception
     {
       //menciptakan kunci-kunci
       KeyPair         sepasang = Utils.bangkitkanSepasangKunciRSA();;

       //menciptakan aliran masukan
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();

       bOut.write(ContohMenciptakanX509V1.generateV1Certificate(sepasang).getEncoded());

       bOut.close();

       InputStream in = new ByteArrayInputStream(bOut.toByteArray());

      //menciptakan pabrik sertifikat
      CertificateFactory pabrik = CertificateFactory.getInstance("X.509","BC");

      //membaca sertifikat
      X509Certificate x509Cert = (X509Certificate)pabrik.generateCertificate(in);

      System.out.println("Issuer: " + x509Cert.getIssuerX500Principal());
  }
}

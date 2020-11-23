package bab6;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

/**
 * Pembangkitan request PKCS #10.
 */
public class ContohPKCS10CertRequest
{
   public static PKCS10CertificationRequest generateRequest(
      KeyPair sepasang)
      throws Exception

   {
      return new PKCS10CertificationRequest(
              "SHA256withRSA",
              new X500Principal("CN=Requested Test Certificate"),
              sepasang.getPublic(),
              null,
              sepasang.getPrivate());
   }

  public static void main(String[] args) throws Exception
  {
      //menciptakan kunci-kunci
      KeyPairGenerator genSepasangKunci = KeyPairGenerator.getInstance("RSA", "BC");

      genSepasangKunci.initialize(1024, Utils.ciptakanAcakTetap());

      KeyPair         sepasang = genSepasangKunci.generateKeyPair();

      PKCS10CertificationRequest request = generateRequest(sepasang);

      PEMWriter   pemWrt = new PEMWriter(
                                          new OutputStreamWriter(System.out));

      pemWrt.writeObject(request);

      pemWrt.close();
   }
}
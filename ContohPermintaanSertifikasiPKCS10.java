package bab6;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

/**
 * Pembangkitan permintaan sertifikasi PKCS #10.
 */
public class ContohPermintaanSertifikasiPKCS10
{
   public static PKCS10CertificationRequest generateRequest(
      KeyPair sepasang)
      throws Exception

   {
      return new PKCS10CertificationRequest(
              "SHA256withRSA",
              new X500Principal("CN=Permintaan Sertifikasi"),
              sepasang.getPublic(),
              null,
              sepasang.getPrivate());
   }

  public static void main(String[] args) throws Exception
  {
      //menciptakan kunci-kunci
      KeyPairGenerator pembangkit = KeyPairGenerator.getInstance("RSA", "BC");

      pembangkit.initialize(1024, Utils.ciptakanAcakTetap());

      KeyPair         sepasang = pembangkit.generateKeyPair();

      PKCS10CertificationRequest permintaan = generateRequest(sepasang);

      PEMWriter   pemWrt = new PEMWriter(
                                          new OutputStreamWriter(System.out));

      pemWrt.writeObject(permintaan);

      pemWrt.close();
   }
}
package bab6;

      import java.io.OutputStreamWriter;
      import java.security.KeyPair;
      import java.security.KeyPairGenerator;
      import java.util.Vector;

      import javax.security.auth.x500.X500Principal;

      import org.bouncycastle.asn1.DEROctetString;
      import org.bouncycastle.asn1.DERSet;
      import org.bouncycastle.asn1.pkcs.Attribute;
      import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
      import org.bouncycastle.asn1.x509.GeneralName;
      import org.bouncycastle.asn1.x509.GeneralNames;
      import org.bouncycastle.asn1.x509.X509Extension;
      import org.bouncycastle.asn1.x509.X509Extensions;
      import org.bouncycastle.jce.PKCS10CertificationRequest;
      import org.bouncycastle.openssl.PEMWriter;

      /**
       * Pembangkitan PKCS #10 request dengan sebuah ekstensi.
       */
      public class ContohEkstensiPKCS10
      {
         public static PKCS10CertificationRequest generateRequest(
            KeyPair sepasang)
            throws Exception
         {
      
      //mencipatkan sebuah nilai ekstensi SubjectAlternativeName
      GeneralNames namaAlternatif = new GeneralNames(
              new GeneralName(GeneralName.rfc822Name, "test@test.test"));

      //menciptakan objek ekstensi dan menambahkannya sebagai atribut
      Vector oids = new Vector();
      Vector nilai2 = new Vector();

      oids.add(X509Extensions.SubjectAlternativeName);
      nilai2.add(new X509Extension(false, new DEROctetString(namaAlternatif)));

      X509Extensions ekstensi = new X509Extensions(oids, nilai2);

      Attribute atribut = new Attribute(
                             PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                             new DERSet(ekstensi));

      return new PKCS10CertificationRequest(
             "SHA256withRSA",
             new X500Principal("CN=Permintaan Sertifikasi"),
             sepasang.getPublic(),
             new DERSet(atribut),
             sepasang.getPrivate());
    }
    public static void main(String[] args) throws Exception
    {
      //menciptakan kunci-kunci
      KeyPairGenerator genSepasangKunci = KeyPairGenerator.getInstance("RSA", "BC");

      genSepasangKunci.initialize(1024, Utils.ciptakanAcakTetap());

      KeyPair sepasang = genSepasangKunci.generateKeyPair();

      PKCS10CertificationRequest request = generateRequest(sepasang);

      PEMWriter       pemWrt = new PEMWriter(
                                       new OutputStreamWriter(System.out));
      pemWrt.writeObject(request);
      pemWrt.close();
  }
}

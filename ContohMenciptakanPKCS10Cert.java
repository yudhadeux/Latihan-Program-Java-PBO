package bab6;

import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * Sebuah contoh dari CA.
 */
public class ContohMenciptakanPKCS10Cert
{
   public static X509Certificate[] bangunRantai() throws Exception
   {
      //menciptakan permintaan sertifikasi
      KeyPair         sepasang = Utils.bangkitkanSepasangKunciRSA();
      PKCS10CertificationRequest permintaan =
                                 ContohEkstensiPKCS10.generateRequest(sepasang);

      //menciptakan sertifikasi akar
      KeyPair          akarPasangan = Utils.bangkitkanSepasangKunciRSA();
      X509Certificate sertifikasiAkar =
                          ContohMenciptakanX509V1.generateV1Certificate(akarPasangan);

      //memvalidasi permintaan sertifikasi
      if (!permintaan.verify("BC"))
      {
         System.out.println("Permintaan gagal diverifikasi!");
         System.exit(1);
      }

      //menciptakan sertifikat menggunakan informasi pada permintaan
      X509V3CertificateGenerator bangkitkanSert = new X509V3CertificateGenerator();

      bangkitkanSert.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
      bangkitkanSert.setIssuerDN(sertifikasiAkar.getSubjectX500Principal());
      
      bangkitkanSert.setNotBefore(new Date(System.currentTimeMillis()));
      bangkitkanSert.setNotAfter(new Date(System.currentTimeMillis() + 50000));
      
      bangkitkanSert.setSubjectDN(permintaan.getCertificationRequestInfo().getSubject());
      bangkitkanSert.setPublicKey(permintaan.getPublicKey("BC"));
      
      bangkitkanSert.setSignatureAlgorithm("SHA256WithRSAEncryption");

      bangkitkanSert.addExtension(X509Extensions.AuthorityKeyIdentifier,
                          false, new AuthorityKeyIdentifierStructure(sertifikasiAkar));

      bangkitkanSert.addExtension(X509Extensions.SubjectKeyIdentifier,

           false, new SubjectKeyIdentifierStructure(permintaan.getPublicKey("BC")));

      bangkitkanSert.addExtension(X509Extensions.BasicConstraints,
                                             true, new BasicConstraints(false));

      bangkitkanSert.addExtension(X509Extensions.KeyUsage,
       true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

       bangkitkanSert.addExtension(X509Extensions.ExtendedKeyUsage,
                      true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

       //mengekstrak atribut permintaan ekstensi
       ASN1Set atribut = permintaan.getCertificationRequestInfo().getAttributes();

       for (int i = 0; i != atribut.size(); i++)
       {
         Attribute attr = Attribute.getInstance(atribut.getObjectAt(i));

         // memproses permintaan ekstensi
         if (attr.getAttrType().equals(
                      PKCSObjectIdentifiers.pkcs_9_at_extensionRequest))
         {
            X509Extensions ekstensi = X509Extensions.getInstance(
                                        attr.getAttrValues().getObjectAt(0));

            Enumeration e = ekstensi.oids();
            while (e.hasMoreElements())
            {
              DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
              X509Extension       ekst = ekstensi.getExtension(oid);

              bangkitkanSert.addExtension(oid, ekst.isCritical(),
                                             ekst.getValue().getOctets());
            }
         }
      }
      X509Certificate sertDikeluarkan = bangkitkanSert.generateX509Certificate(
                                                     akarPasangan.getPrivate());

      return new X509Certificate[] { sertDikeluarkan, sertifikasiAkar };
    }
    public static void main(String[] args) throws Exception
    {
      X509Certificate[] rantai = bangunRantai();

      PEMWriter      pemWrt = new PEMWriter(
                                      new OutputStreamWriter(System.out));

      pemWrt.writeObject(rantai[0]);
      pemWrt.writeObject(rantai[1]);

      pemWrt.close();
   }
}


package bab4;

import java.security.Key;
import java.security.KeyPair;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

public class ContohPembungkusanKunciRSA
{
    public static void main(String[] args) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecureRandom acak = new SecureRandom();

        KeyPairGenerator pembangkit = KeyPairGenerator.getInstance("RSA", "BC");
        pembangkit.initialize(1024, acak);

        KeyPair      pasanganKunci = pembangkit.generateKeyPair();
        Key          kunciPembungkus = Utils.ciptakanKunciUntukAES(256, acak);

        //membungkus kunci privat RSA
        cipher.init(Cipher.WRAP_MODE, kunciPembungkus);

        byte[] kunciTerbungkus = cipher.wrap(pasanganKunci.getPrivate());

        //membuka kunci privat RSA
        cipher.init(Cipher.UNWRAP_MODE, kunciPembungkus);

        Key kunci = cipher.unwrap(kunciTerbungkus, "RSA", Cipher.PRIVATE_KEY);

        if (pasanganKunci.getPrivate().equals(kunci))
        {
            System.out.println("Kunci diekstrak.");
        }
         else
         {
            System.out.println("Kunci gagal diekstrak.");
         }
    }
}
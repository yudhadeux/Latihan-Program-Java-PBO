package bab2;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class ContohPembungkusanKunciSederhana
{
    public static void main(String[] args) throws Exception
    {
        //menciptakan sebuah kunci untuk membungkus
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(128);

        Key kunciUntukDibungkus = generator.generateKey();

        System.out.println("masukan    : " +
                                     Utils.toHex(kunciUntukDibungkus.getEncoded()));

        //menciptakan sebuah pembungus dan melakukan pembungkusan
        Cipher cipher = Cipher.getInstance("AESWrap", "BC");

        KeyGenerator KunciBangkit = KeyGenerator.getInstance("AES", "BC");
        KunciBangkit.init(256);

        Key KunciBungkus = KunciBangkit.generateKey();

        cipher.init(Cipher.WRAP_MODE, KunciBungkus);

        byte[] kunciDibungkus = cipher.wrap(kunciUntukDibungkus);

        System.out.println("dibungkus : " + Utils.toHex(kunciDibungkus));

        //membuka kunci terbungkus
        cipher.init(Cipher.UNWRAP_MODE, KunciBungkus);

        Key kunci = cipher.unwrap(kunciDibungkus, "AES", Cipher.SECRET_KEY);

        System.out.println("dibuka: " + Utils.toHex(kunci.getEncoded()));
    }
}
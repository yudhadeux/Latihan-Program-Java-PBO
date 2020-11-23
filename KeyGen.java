import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGen {

public static void main(String[] args) throws Exception {
String algorithm = "RSA";
KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
generator.initialize(1024);
KeyPair keyPair = generator.generateKeyPair();
System.out.println(keyPair.getClass().getName());
System.out.println(keyPair.getPublic().getClass().getName());
System.out.println(keyPair.getPublic());
System.out.println(keyPair.getPrivate());
}

}
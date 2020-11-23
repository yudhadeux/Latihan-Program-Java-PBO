package bab1;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

/**
 * Daftar kapabilitas untuk cipher, perjanjian kunci, mac, message digest
 * sidik digital, dan objek-objek lain dalam provider BC.
 */
public class DaftarKapabilitasBouncyCastle
{
    public static void main(
        String[]    args)
    {
        Provider      provider = Security.getProvider("BC");

        Iterator it = provider.keySet().iterator();

        while (it.hasNext())
        {
            String    entri = (String)it.next();

            if (entri.startsWith("Alg.Alias."))
            {
                entri = entri.substring("Alg.Alias.".length());
            }

            String kelasFaktori = entri.substring(0, entri.indexOf('.'));
            String nama = entri.substring(kelasFaktori.length() + 1);

            System.out.println(kelasFaktori + ": " + nama);
        }
    }
}


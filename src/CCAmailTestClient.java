import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;

/**
 * Created by nicholas on 11/11/16.
 */
public class CCAmailTestClient {
    static String path;
    static File inFile;

    public static void main(String[] args) {
        final int LOOP_COUNT = 16;
        final String STATS_FILE = "/statistics.csv";

        if (args.length < 1) {
            printUsage();
        }

        if (args.length == 2) {
            path = args[1];
            inFile = new File(args[0]);
        } else {
            inFile = new File(args[0]);
            path = inFile.getParent();
        }

        // Since GCM allows for additional authenticated data, we can encrypt the file and use the unencrypted email
        // address as an additional part of the tag.
        String emailAddress = "mckinnnd@uw.edu";

        try {
            // Generate an encryption key.  In a real-world scenario, this will already exist.
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey keymat = keyGen.generateKey();
            FileOutputStream stats = new FileOutputStream(path + STATS_FILE, true);

            for (int i = 0; i < LOOP_COUNT; i++) {
                CCAmail testCipher = new CCAmail(keymat);

                // Let's encrypt!
                long start_time = System.nanoTime();
                testCipher.encryptFile(inFile, new File(path + "/ciphertext.txt"), emailAddress);
                long stop_time = System.nanoTime();

                String outstring = "encrypt," + ((stop_time - start_time)/1000000) + '\n';
                stats.write(outstring.getBytes());

                // Now let's go the other way
                start_time = System.nanoTime();
                testCipher.decryptFile(new File(path + "/ciphertext.txt"), new File(path + "/recovered_pt.txt"), emailAddress);
                stop_time = System.nanoTime();
                outstring = "decrypt," + ((stop_time - start_time)/1000000) + '\n';
                stats.write(outstring.getBytes());
            }

            stats.close();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

    public static void printUsage() {
        System.out.println("Usage: CCAmailTest plaintextFile <outputFile>");
    }
}

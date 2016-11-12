import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;

/**
 * Created by nicholas on 11/11/16.
 */
public class CCAmailTestClient {
    static String path;
    static File inFile;

    public static void main(String[] args) {
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

            CCAmail testCipher = new CCAmail(keymat);
            testCipher.encryptFile(inFile, new File(path + "/ciphertext.txt"), emailAddress);

            // Scramble stuff to test
            testCipher.generateNewIV();

            // Now let's go the other way
            testCipher.decryptFile(new File(path + "/ciphertext.txt"), new File(path + "/recovered_pt.txt"), emailAddress);

        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }


    }

    public static void printUsage() {
        System.out.println("Usage: CCAmailTest plaintextFile <outputFile>");
    }
}

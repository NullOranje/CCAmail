/**
 * Created by nicholas on 11/11/16.
 */

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.*;

public class CCAmail {
	// The maximum GCM tag legnth is 16 bytes.  This is also the preferred length per SP 800-38D
	private final int GCM_TAG_LENGTH = 16;
	private final int GCM_IV_LENGTH = 12;

	// javax.crypto.cipher is the main cryptographic engine for Java
	private Cipher cipher;

	// These are the two secret keys.  One key is for the ciphertext encryption, the other is for the MAC
	private SecretKey cryptoKey;

	// This is where our IV will go
	private byte[] IV;

	CCAmail(SecretKey cK) throws Exception {
		// Store our inputs
		this.cryptoKey = cK;

		// Generate a new Cipher object that will use the AES block cipher in GCM mode
		this.cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");

		// Create space for an IV and generate a new IV
		// NB: The IV is the critical security value for GCM
		this.IV = new byte[GCM_IV_LENGTH];  // Per SP 800-38D, keep the IV to a 96-bit string
	}

	public void encryptFile(File inFile, File outFile, String emailAddress) {
		generateNewIV();
		// Per SP 800-38D, the tag length
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, this.IV);

		try {
			// Initialize the cipher object
			cipher.init(Cipher.ENCRYPT_MODE, cryptoKey, gcmParameterSpec);

			// Per JDK8 documentation, must update additional authenticated data before anything else happens
			cipher.updateAAD(emailAddress.getBytes());

			// Get our message
			long fileSize = inFile.length();
			if (fileSize > Integer.MAX_VALUE)
				throw new IOException("Max file size exceeded");

			FileInputStream fis = new FileInputStream(inFile);
			byte[] buffer = new byte[cipher.getBlockSize()];
			FileOutputStream fos = new FileOutputStream(outFile);

			// Store the IV
			fos.write(cipher.getIV());
			byte[] encrypted;

			// Encrypt the file
			// Read all but the last block
			double blockCount = (double)fileSize / cipher.getBlockSize();
			int loopCount = (int)Math.ceil(blockCount) - 1;

			for (int i = 0; i < loopCount; i++) {
				fis.read(buffer);
				fos.write(cipher.update(buffer));
			}

			// If the last block is undersized, don't create a full-sized block
			int bufferSize = (int)fileSize - (loopCount * cipher.getBlockSize());
			buffer = new byte[cipher.getBlockSize()];

			fis.read(buffer);
			// fos.write(cipher.update(buffer));

			// Closeout the cipher and output the tag
			fos.write(cipher.doFinal(buffer));

			// Cleanup
			fos.close();
			fis.close();

		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
	}

	public void decryptFile(File inFile, File outFile, String emailAddress) {

		try {
			long fileSize = inFile.length();
			if (fileSize > Integer.MAX_VALUE)
				throw new IOException("Max file size exceeded");

			FileInputStream fis = new FileInputStream(inFile);
			// Get our IV from the file
			fis.read(IV);
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, this.IV);
			cipher.init(Cipher.DECRYPT_MODE, cryptoKey, gcmParameterSpec);
			cipher.updateAAD(emailAddress.getBytes());

			int blockCount = (int)(fileSize - 12) / cipher.getBlockSize();
			byte[] cipherText = new byte[blockCount * cipher.getBlockSize()];
			byte[] buffer = new byte[cipher.getBlockSize()];

			for (int i = 0; i < blockCount; i++) {
				fis.read(buffer);
				updatePlainText(cipherText, buffer, i, cipher.getBlockSize());
			}

			byte[] plainText = cipher.doFinal(cipherText);

			System.out.println("Success!");
			fis.close();

			FileOutputStream fos = new FileOutputStream(outFile);
			for (int i = 0; i < plainText.length; i++)
				fos.write(plainText[i]);

			fos.close();

		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
	}

	public void generateNewIV() {
		SecureRandom srng = new SecureRandom();
		srng.nextBytes(this.IV);
	}

	void updatePlainText(byte[] PT, byte[] buffer, int block, int blockSize) {
		for (int i = 0; i < buffer.length; i++)
			PT[block * blockSize + i] = buffer[i];
	}
}

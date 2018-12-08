import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/**
 * Includes static methods for encrypting and decrypting byte arrays using
 * public key/private key encrypting/decrypting.
 * @author pethrus
 *
 */
public class HandshakeCrypto {

	/**
	 * Encrypts given byte array with the provided asymmetric key
	 * (Public or Private)
	 * @param plaintext The byte array to be encrypted
	 * @param key The public key used to encrypt the byte array
	 * @return Encrypted byte array
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher encrypt = Cipher.getInstance("RSA");
		encrypt.init(Cipher.ENCRYPT_MODE, key);
		return encrypt.doFinal(plaintext);
	}

	/**
	 * Decrypts the given byte array with the provided asymmetric key
	 * (Public or Private)
	 * @param ciphertext
	 * @param key
	 * @return Decrypted byte array
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher decrypt = Cipher.getInstance("RSA");
		decrypt.init(Cipher.DECRYPT_MODE, key);
		return decrypt.doFinal(ciphertext);
	}
	
	/** 
	 * Retrieves the Public key from a certificate file
	 * @param certfile The certificate file from which to retrieve the Public key
	 * @return The extracted public key
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	public static PublicKey getPublicKeyFromCertFile(String certFile) throws CertificateException, IOException {
		MyCertificate certificate = new MyCertificate(new File(certFile));
		return certificate.getPublicKey();
	}
	
	/** 
	 * Retrieves the Private key from a certificate file
	 * @param keyfile The keyfile from which to retrieve the Private key
	 * @return The extracted private key
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(keyfile);
		FileInputStream fileStream = new FileInputStream(file);
		DataInputStream dataStream = new DataInputStream(fileStream);
		byte[] keyBytes = new byte[(int) file.length()];
		dataStream.readFully(keyBytes);
		dataStream.close();
		
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		return kf.generatePrivate(spec);
	}
}

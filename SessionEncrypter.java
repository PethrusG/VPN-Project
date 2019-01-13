import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import java.util.Base64;

/**
 * Performs encryption on a stream of data using AES in CTR mode
 * @author pethrus gärdborn
 *
 */
public class SessionEncrypter {

	SessionKey key;
	Cipher cipher;
	IvParameterSpec iv1;
	byte[] iv;
	
	/**
	 * 
	 * @param keylength
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, 
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		
		this.key = new SessionKey(keylength);
		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
		this.iv1 = new IvParameterSpec(this.key.getSecretKey().getEncoded());
		
		SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] iv = new byte[cipher.getBlockSize()];
		randomSecureRandom.nextBytes(iv);
		this.iv1 = new IvParameterSpec(iv);
		
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key.getSecretKey(),
				this.iv1);
	}
	
	SessionEncrypter(String key, String iv) throws NoSuchAlgorithmException, 
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		
		this.key = new SessionKey(key);
		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
		this.iv1 = new IvParameterSpec(Base64.getDecoder().decode(iv));
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key.getSecretKey(),
				this.iv1);
	}

	SessionEncrypter(byte[] key, String iv) throws NoSuchAlgorithmException, 
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		
		this.key = new SessionKey(key);
		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
		this.iv1 = new IvParameterSpec(Base64.getDecoder().decode(iv));
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key.getSecretKey(),
				this.iv1);
	}
	/**
	 * Returns the key created by SessionEncrypter encoding it using Base64
	 * @return The key of SessionEncrypter encoded with Base64 as a String
	 */
	String encodeKey() {
		return this.key.encodeKey();
	}
	
	/**
	 * Returns the initialization vector encoded as a Base64 String
	 * @return a Base64-encoded String initialization vector 
	 */
	String encodeIV() {
		return Base64.getEncoder().encodeToString(this.iv1.getIV());
	}
	
	
	/**
	 * Receives cleartext data as an OutputStream, encrypts it and returns it as
	 * a CipherOutputStream
	 * @param output The cleartext data
	 * @return The encrypted data
	 */
	CipherOutputStream openCipherOutputStream(OutputStream output) {
		// TODO: Should we use the initialization vector here??
		return new CipherOutputStream(output, cipher);
	}
}

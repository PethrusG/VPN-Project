import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Performs decryption on a stream of data using AES in CTR mode
 * @author pethrus
 *
 */
public class SessionDecrypter {

	SessionKey key;
	Cipher cipher;
//	IvParameterSpec iv;
	byte[] iv;
	/**
	 * Instantiates a SessionDecrypter using the provided Base64-encoded key and the 
	 * Base64-encoded provided initialization vector 
	 * @param key The Base64-encoded key as a String
	 * @param iv The Base64-encoded initialization vector 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	SessionDecrypter(String key, String iv) throws InvalidKeyException, NoSuchAlgorithmException, 
	NoSuchPaddingException, InvalidAlgorithmParameterException {
		this.key = new SessionKey(key);
		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
//		this.iv = cipher.getIV();
//		this.iv = new IvParameterSpec(this.key.getSecretKey().getEncoded());
		this.iv = Base64.getDecoder().decode(iv);
		this.cipher.init(Cipher.DECRYPT_MODE, this.key.getSecretKey(), 
				new IvParameterSpec(this.iv));
	}
	
	/**
	 * Receives encrypted data as an InputStream and returns the decrypted data
	 * @param input The encrypted data stream as an InputStream
	 * @return The decrypted data stream as a CipherInputStream
	 */
	CipherInputStream openCipherInputStream(InputStream input) {
		return new CipherInputStream(input, cipher);
	}
}

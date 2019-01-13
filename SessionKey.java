import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
/**
 * Represents the symmetric key used in a session between two parties in the VPN
 * @author pethrus gärdborn
 *  
 */

class SessionKey {

	public static final String ALGORITHM = "AES";

    private SecretKey secretKey;
    private KeyGenerator keyGen;

   /**
    * Generates a <code> SecretKey </code> with the length of <code> keylength </code>. 
    * @param keylength The length of the key to be generated
    * @throws NoSuchAlgorithmException 
    */
    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        this.keyGen = KeyGenerator.getInstance("AES");
    	this.keyGen.init(keylength);
        this.secretKey = keyGen.generateKey();
    }
    
    public SessionKey(byte[] secretKey) {
    	this.secretKey = new SecretKeySpec(secretKey, ALGORITHM);
    }

/**
 * Receives a Base64-encoded <code> String </code> and assigns that key
 * to <code> SessionKey </code>
 * @param encodeKey The Base64-encoded key to be assigned to <code> SessionKey </code>
 * @throws NoSuchAlgorithmException 
 */
    public SessionKey(String encodeKey) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(Base64.getDecoder().decode(encodeKey), "AES");
//        this.keyGen = KeyGenerator.getInstance("AES");
//    	this.keyGen.init(128);
//        this.secretKey = keyGen.generateKey();
    }
/**
 * Returns the <code> SecretKey </code> kept in this class    
 * @return the <code> SecretKey </code> kept in this class    

 */
    public SecretKey getSecretKey() {
    	return this.secretKey;
    }
/**
 * Encodes the <code> SecretKey </code> of this class with Base64 to enable exportion
 * of key to other party.   
 * @return the Base64-encoded <code> SecretKey </code> as a <code> String </code>
 */
    public String encodeKey() {
    	return Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
    }
    
/**
 * Decodes a Base-64 encoded String to a byte array.
 * @param encodeKey The Base64-encoded byte array to be decoded
 * @return a byte-array decoded from Base64-encoding
 */
    public byte[] decodeKey(String encodeKey) {
    	return Base64.getDecoder().decode(encodeKey);

    }
}
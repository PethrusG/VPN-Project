import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import java.util.Base64;
/**
 * Methods to test functionality in other classes.
 * Note that it is necessary to make the private methods pubic in SessionKey
 * to be able to perform these tests.
 * @author pethrus
 *
 */
public class Testing {
	
	public void fieldOfKey (SessionKey sessionKey) {
		System.out.println("Key field: " + String.format("%d", sessionKey.getSecretKey().serialVersionUID));
	}
	
	public void rawEncodingOfKey (SessionKey sessionKey) {
        System.out.print("Raw encoding of secret key: ");
        byteArrayToHexAndPrint(sessionKey.getSecretKey().getEncoded());
	}
	public void testBase64() {
		String encoded = Base64.getEncoder().encodeToString("Hello".getBytes());
		System.out.println(encoded);   // Outputs "SGVsbG8="
		String decoded = new String(Base64.getDecoder().decode(encoded.getBytes()));
		System.out.println(decoded);    // Outputs "Hello"     	
	}
	public void encodeAndDecodeKey(SessionKey sessionKey) throws NoSuchAlgorithmException {
//		String str = Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
		String keyEncoded = sessionKey.encodeKey();
		System.out.println("Key encoded to Base64: " + keyEncoded);
		byte [] arr = sessionKey.decodeKey(keyEncoded);
		System.out.print("Base64-encoded key decoded back to original: ");
	    byteArrayToHexAndPrint(arr);      	
	}
		
	private void byteArrayToHexAndPrint(byte [] array) {
		StringBuilder sb = new StringBuilder();
		for (byte b : array) {
			sb.append(String.format("%02X ", b));
		}
		System.out.println(sb.toString());
	}
}

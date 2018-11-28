import java.security.NoSuchAlgorithmException;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		SessionKey sessionKey = new SessionKey(192);
		SessionKey sessionKey1 = new SessionKey(sessionKey.encodeKey());
		Testing test = new Testing();
		test.fieldOfKey(sessionKey1);
		test.rawEncodingOfKey(sessionKey1);
		test.encodeAndDecodeKey(sessionKey1);
		
//	    SessionKey key1 = new SessionKey(128);
//        SessionKey key2 = new SessionKey(key1.encodeKey());
//        if (key1.getSecretKey().equals(key2.getSecretKey())) {
//            System.out.println("Pass");
//        }
//        else {
//            System.out.println("Fail");
//        }    	
	}
}

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * Simple program which, given a user certificate and CA certificate, verifies the
 * user certificate file by decrypting the signature of the user certifiacte using
 * the CAs public key and matching it against the hashed cleartext of the user 
 * certificate. Also, the validity of the dates are checked.
 * @author pethrus
 */
public class VerifyCertificate {

	// args[0] is CA certificate file
	// args[1] is user certificate file
	public static void main(String[] args) throws CertificateException, IOException {
	
		MyCertificate caCertificate = new MyCertificate(new File(args[0]));
		MyCertificate userCertificate = new MyCertificate(new File(args[1]));

//    1. Print the DN for the CA (one line)
		System.out.println(caCertificate.getDnCleartext());

//    2. Print the DN for the user (one line)
		System.out.println(userCertificate.getDnCleartext());

//    3. Verify the user certificate
//    4. Print "Pass" if check 3 and 4 are successful
		VerifyMyCertificate verifyMyCertificate = new VerifyMyCertificate(caCertificate, userCertificate);
		if (verifyMyCertificate.verifyCertificate())
			System.out.println("Pass");

//    5. Print "Fail" if any of them fails, followed by an explanatory comment of how the verification failed
    	// TODO: Expand this with explanatory comment on why it failed, possibly using exception handling.
		else
			System.out.println("Fail");
	}
}
// TODO: Further testing
// Invoke every exception
// Try certificates with invalid dates
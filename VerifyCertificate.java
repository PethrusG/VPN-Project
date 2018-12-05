import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
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
//		VerifyMyCertificate verifyMyCertificate = new VerifyMyCertificate(caCertificate, userCertificate);
//		if (verifyMyCertificate.verifyCertificate())
//			System.out.println("Pass");

//    5. Print "Fail" if any of them fails, followed by an explanatory comment of how the verification failed
    	// TODO: Expand this with explanatory comment on why it failed, possibly using exception handling.
//		else
//			System.out.println("Fail");
		
//		certificateVerification = new CertificateVerification(args[0], args[1]);
//		out.println(certificateVerification.getUserDnCleartext());
//		out.println(certificateVerification.getCaDnCleartext());
//		
//		if(certificateVerification.verifyCaCertificate() && certificateVerification.verifyUserCertificate())
//			out.println("Pass");
//		else
//			out.println("Fail");
//		
	}
}

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;

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


class MyCertificate {

	X509Certificate myCertificate;

	public MyCertificate(File certFile) throws CertificateException, IOException {
		FileInputStream certFileStream = new FileInputStream(certFile);
		BufferedInputStream certBufferStream = new 
				BufferedInputStream(certFileStream);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
	
        while (certBufferStream.available() > 0)
        	this.myCertificate = (X509Certificate) cf.generateCertificate(certBufferStream);
	}
	
	public String getDnCleartext() {
		return myCertificate.getSubjectX500Principal().getName();
	}
}


class VerifyMyCertificate {
	
	MyCertificate userCertificate;
	MyCertificate caCertificate;
	
	public VerifyMyCertificate(MyCertificate caCertificate, MyCertificate userCertificate) {
		this.caCertificate = caCertificate;
		this.userCertificate = userCertificate;
	}
	
	public boolean verifyCertificate() {
		if (compareSignatureWithHash() && checkDatesValidity())
			return true;
		return false;
	}
	
	private boolean compareSignatureWithHash() {
	// TODO: Need public key file!	
		try {
			this.userCertificate.myCertificate.verify(this.caCertificate.myCertificate.getPublicKey());
		}
		catch (NoSuchAlgorithmException e) {
			System.err.println("Caught NoSuchAlgorithmException" + e.getMessage());
		}
		catch (InvalidKeyException e) {
			System.err.println("Caught InvalidKeyException" + e.getMessage());
		}
		catch (NoSuchProviderException e) {
			System.err.println("Caught NoSuchProviderException" + e.getMessage());
		}
		catch (SignatureException e) {
			System.err.println("Caught SignatureException" + e.getMessage());
		}
		catch (CertificateException e) {
			System.err.println("Caught CertificateException" + e.getMessage());
		}
		return true;	
	}
		
	private boolean checkDatesValidity() {
		Date date = new Date();
		try {
			this.userCertificate.myCertificate.checkValidity();
		}
		catch (CertificateExpiredException e) {
			System.err.println("Caught CertificateExpiredException" + e.getMessage());
		}
		catch (CertificateNotYetValidException e) {
			System.err.println("Caught CertificateNotYetValidException" + e.getMessage());
		}
		return true;
	}
}
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;

public class VerifyMyCertificate {
	
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
		try {
			this.userCertificate.myCertificate.verify(this.caCertificate.myCertificate.getPublicKey());
//			throw new NoSuchAlgorithmException();
		}
		catch (NoSuchAlgorithmException e) {
			System.err.println("Caught NoSuchAlgorithmException");
		}
		catch (InvalidKeyException e) {
			System.err.println("Caught InvalidKeyException");
		}
		catch (NoSuchProviderException e) {
			System.err.println("Caught NoSuchProviderException");
		}
		catch (SignatureException e) {
			System.err.println("Caught SignatureException");
		}
		catch (CertificateException e) {
			System.err.println("Caught CertificateException");
		}
		return true;	
	}
		
	private boolean checkDatesValidity() {
		Date date = new Date();
		try {
			this.userCertificate.myCertificate.checkValidity();
		}
		catch (CertificateExpiredException e) {
			System.err.println("Caught CertificateExpiredException");
		}
		catch (CertificateNotYetValidException e) {
			System.err.println("Caught CertificateNotYetValidException");
		}
		return true;
	}

}
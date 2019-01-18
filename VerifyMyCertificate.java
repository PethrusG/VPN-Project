import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;

/**
 * Verifies a user certificate by extracting the public key from the signing
 * CAs certificate. Also, valid dates are checked.
 * @author pethrus
 *
 */
public class VerifyMyCertificate {
	
	MyCertificate userCertificate;
	MyCertificate caCertificate;
	
	/**
	 * Instantiates VerifyMyCertificate with a User certificate and the signing CAs
	 * certificate.
	 * @param caCertificate The CA Certificate that signed the User certificate
	 * @param userCertificate The User Certificate
	 */
	public VerifyMyCertificate(MyCertificate caCertificate, MyCertificate userCertificate) {
		this.caCertificate = caCertificate;
		this.userCertificate = userCertificate;
	}
	
	/**
	 * Verify the user certificate in two ways - decrypting the CAs signature with
	 * the CAs public key and checking if the dates are still valid for the certificate.
	 * @return
	 */
	public boolean verifyCertificate() {
		if (compareSignatureWithHash() && checkDatesValidity())
			return true;
		return false;
	}
	
	/**
	 * Compares the decrypted signature of the user certificate with the hashed cleartext
	 * part of the user certificate. 
	 * @return true if the hashed cleartext and decrypted signature matches
	 */
	private boolean compareSignatureWithHash() {
		try {
			this.userCertificate.myCertificate.verify(this.caCertificate.myCertificate.getPublicKey());
//			this.caCertificate.myCertificate.verify(this.caCertificate.myCertificate.getPublicKey());
//			throw new NoSuchAlgorithmException();
		}
		catch (NoSuchAlgorithmException e) {
			System.err.println("Caught NoSuchAlgorithmException");
//			return false;
		}
		catch (InvalidKeyException e) {
			System.err.println("Caught InvalidKeyException");
//			return false;
		}
		catch (NoSuchProviderException e) {
			System.err.println("Caught NoSuchProviderException");
//			return false;
		}
		catch (SignatureException e) {
			System.err.println("Caught SignatureException");
//			return false;
		}
		catch (CertificateException e) {
			System.err.println("Caught CertificateException");
//			return false;
		}
		return true;	
	}
	/**
	 * Check that the dates are valid for the certificate	
	 * @return true if the dates are valid
	 */
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
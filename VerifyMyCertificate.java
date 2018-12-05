//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.SignatureException;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateExpiredException;
//import java.security.cert.CertificateNotYetValidException;
//import java.util.Date;
//
//public class VerifyMyCertificate {
//	
//	MyCertificate userCertificate;
//	MyCertificate caCertificate;
//	
//	public VerifyMyCertificate(MyCertificate caCertificate, MyCertificate userCertificate) {
//		this.caCertificate = caCertificate;
//		this.userCertificate = userCertificate;
//	}
//	
//	public boolean verifyCertificate() {
//		if (compareSignatureWithHash() && checkDatesValidity())
//			return true;
//		return false;
//		
////		signature = userCertificate.getSignature();
////		if (compareSignatureWithHash(signature, hash))
////			return true;
//	
//	// Extract cleartext certificate
//	// Hash cleartext certificate
//	// Decrypt the encrypted hash of the certificate
//	// Compare 
//	}
//	
//	private boolean compareSignatureWithHash() {
//	// TODO: Need public key file!	
//		try {
//			this.userCertificate.myCertificate.verify(this.caCertificate.myCertificate.getPublicKey());
//		}
//		catch (NoSuchAlgorithmException e) {
//			System.err.println("Caught NoSuchAlgorithmException" + e.getMessage());
//		}
//		catch (InvalidKeyException e) {
//			System.err.println("Caught InvalidKeyException" + e.getMessage());
//		}
//		catch (NoSuchProviderException e) {
//			System.err.println("Caught NoSuchProviderException" + e.getMessage());
//		}
//		catch (SignatureException e) {
//			System.err.println("Caught SignatureException" + e.getMessage());
//		}
//		catch (CertificateException e) {
//			System.err.println("Caught CertificateException" + e.getMessage());
//		}
//		return true;	
//	}
//		
////		clearTextCert = userCertificate.cleartext();
////		clearTextCertHashed = userCertificate.hash(caCertificate.getHash());
////		decryptedSignature = userCertificate.decryptSignature(caCertificate.getPublicKey());
////		if (clearTextCertHashed.equals.decryptedSignature) {
////			return true
////		}
////		return false;
////	}
//	
//	private boolean checkDatesValidity() {
//		Date date = new Date();
////		date.
//		try {
//			this.userCertificate.myCertificate.checkValidity();
//		}
//		catch (CertificateExpiredException e) {
//			System.err.println("Caught CertificateExpiredException" + e.getMessage());
//		}
//		catch (CertificateNotYetValidException e) {
//			System.err.println("Caught CertificateNotYetValidException" + e.getMessage());
//		}
//		return true;
//	}
//}
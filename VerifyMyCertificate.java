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
		
		else
			return false;
		
		signature = userCertificate.getSignature();
		if (compareSignatureWithHash(signature, hash))
			return true;
	
	// Extract cleartext certificate
	// Hash cleartext certificate
	// Decrypt the encrypted hash of the certificate
	// Compare 
	}
	
	private boolean compareSignatureWithHash() {
		clearTextCert = userCertificate.cleartext();
		clearTextCertHashed = userCertificate.hash(caCertificate.getHash());
		decryptedSignature = userCertificate.decryptSignature(caCertificate.getPublicKey());
		if (clearTextCertHashed.equals.decryptedSignature) {
			return true
		}
		return false;
	}
	
	private boolean checkDates() {
		return true;
	// TODO: Implement!
//		if(userCertificate.getValidityDate < todaysDate)
//			return true;
//		else
//			return false;
	}
}

	private checkDatesValidity() {
		
	}

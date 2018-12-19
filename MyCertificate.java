import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 *
 * @author pethrus
 *
 */
public class MyCertificate {

	X509Certificate myCertificate;

	/** 
	 * Instantiates a certificate of the type X509 based on a certificate file
	 * @param certFile A certificate file
	 * @throws CertificateException
	 * @throws IOException
	 */
	public MyCertificate(File certFile) throws CertificateException, IOException {
		FileInputStream certFileStream = new FileInputStream(certFile);
		BufferedInputStream certBufferStream = new 
				BufferedInputStream(certFileStream);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
	
        while (certBufferStream.available() > 0)
        	this.myCertificate = (X509Certificate) cf.generateCertificate(certBufferStream);
	}
	
	public MyCertificate(X509Certificate certificate) {
		this.myCertificate = certificate;
	}

	/**
	 * Retrieves the Distinguised name of the certificate
	 * @return Distinguished name of the certificate
	 */
	public String getDnCleartext() {
		return myCertificate.getSubjectX500Principal().getName();
	}

	/** Retrieves the public key of the certificate
	 * 
	 * @return public key of the certificate
	 */
	public PublicKey getPublicKey() {
		return myCertificate.getPublicKey();
	}
}

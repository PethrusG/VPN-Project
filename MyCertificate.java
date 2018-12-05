import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MyCertificate {

	X509Certificate myCertificate;

	// TODO: USE X509 METHODS "RETURNdN" TO RETRIEVE NAME OF CERTIFICATE
	
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
	
	
	

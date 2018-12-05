import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class CertificateVerification {

	Certificate userCertificate;
	Certificate caCertificate;
	
	public CertificateVerification(File caFile, File userFile) throws CertificateException, IOException {
		FileInputStream userFileStream = new FileInputStream(userFile);
		BufferedInputStream userBufferStream = new 
				BufferedInputStream(userFileStream);

		FileInputStream caFileStream = new FileInputStream(caFile);
		BufferedInputStream caBufferStream = new 
				BufferedInputStream(caFileStream);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
	
        while (userBufferStream.available() > 0)
        	this.userCertificate = cf.generateCertificate(userBufferStream);
        while (caBufferStream.available() > 0)
        	this.userCertificate = cf.generateCertificate(caBufferStream);
	}
	
	public String getUserDnCleartext() {
		
	}
	
	public String getCaDnCleartext() {
		
	}
	
	public boolean verifyCaCertificate() {
		
	}
	
	public boolean verifyuserCertificate() {
		
	}
}

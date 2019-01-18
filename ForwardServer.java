/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.lang.AssertionError;
import java.lang.Integer;
import java.util.ArrayList;
import java.util.Arrays;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.StringTokenizer;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.security.Key;
import java.security.cert.CertificateFactory;
 
public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String SERVERFORWARDERHOST = "localhost";
    public static final String SERVERFORWARDERPORT = "6789";
    public static final String PROGRAMNAME = "ForwardServer";
    public static final String CACERTIFICATE = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/ca.pem";
    public static final String FORWARDSERVERCERT = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/server.pem";
    public static final int SECRETKEY = 128;
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    private MyCertificate forwardClientCertificate;
    private SessionKey sessionKey;
    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* Handshake phase */ 
        
        // Receive client's certificate
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);
        
        Logger.log("ForwardServer connected to: " + clientSocket.getRemoteSocketAddress());
        
        int port = Integer.parseInt(arguments.get("handshakeport"));
//        MyCertificate caCertificate = new MyCertificate(new File(CACERTIFICATE));
        MyCertificate caCertificate = new MyCertificate(new File(arguments.get("cacert")));
        
        
        if(clientHello.getParameter("MessageType").equals("ClientHello")) {
        	
        	// Retrieve ForwardClient's certificate 
        	byte[] forwardClientCertificateBytes = 
        			Base64.getDecoder().
        			decode(clientHello.getParameter("Certificate"));
        	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        	InputStream in = new ByteArrayInputStream(forwardClientCertificateBytes);
        	X509Certificate forwardClientCertificateX = 
        			(X509Certificate)certFactory.generateCertificate(in);
//        	MyCertificate forwardClientCertificate = new MyCertificate(forwardClientCertificateX);
        	forwardClientCertificate = new MyCertificate(forwardClientCertificateX);
        	
        	// Verify certificate
			VerifyMyCertificate verifyMyCertificate = new VerifyMyCertificate(
					caCertificate, forwardClientCertificate);
			if (verifyMyCertificate.verifyCertificate())
				System.out.println("ForwardClient's certificate verified");
			// TODO: Abort session if certificate cannot be verified!
			else
				System.out.println("Could not verify ForwardClient's certificate");
        }
        
        // Send certificate to ForwardClient
//		MyCertificate userCertificate = 
//				new MyCertificate(new File(FORWARDSERVERCERT));
		MyCertificate userCertificate = 
				new MyCertificate(new File(arguments.get("usercert")));
		
		byte[] userCertificateToBytes = 
				userCertificate.myCertificate.getEncoded();
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.putParameter("MessageType", "ServerHello");
        String userCertificateToString = 
        		Base64.getEncoder().encodeToString(userCertificateToBytes);
        serverHello.putParameter("Certificate", userCertificateToString);
        serverHello.send(clientSocket);
        
        // Receive client request for target host & port
        HandshakeMessage clientRequest = new HandshakeMessage();
        clientRequest.recv(clientSocket);
        if(clientRequest.getParameter("MessageType").equals("Forward")) {
        	targetHost = clientRequest.getParameter("TargetHost");
        	targetPort = Integer.parseInt(clientRequest.getParameter("TargetPort"));
        	Logger.log("From ClientServer: Target port is: " + targetPort + 
        			"\n Target host is: " + targetHost);
        }
        // Generate session key and iv. Encrypt and encode session key and IV.
        sessionEncrypter = new SessionEncrypter(SECRETKEY);
        byte [] sessionKeyBytes = sessionEncrypter.key.getSecretKey().getEncoded();
        byte [] sessionKeyEncrypted = HandshakeCrypto.encrypt(sessionKeyBytes, 
        		forwardClientCertificate.getPublicKey());
        String sessionKeyEncoded = Base64.getEncoder().encodeToString(
        		sessionKeyEncrypted);

        byte [] sessionIv = sessionEncrypter.iv1.getIV();
		System.out.println("In Forward Server: iv before encryption: " + Arrays.toString(sessionIv));
        byte []  sessionIvEncrypted = HandshakeCrypto.encrypt(sessionIv, 
        		forwardClientCertificate.getPublicKey());
		System.out.println("In Forward Server: iv after encryption: " + Arrays.toString(sessionIvEncrypted));

        String sessionIvEncoded = Base64.getEncoder().encodeToString(
        		sessionIvEncrypted);
		System.out.println("In Forward Server: iv after encryption and encoding: " + Arrays.toString(sessionIvEncoded.getBytes()));

        // Generate session decrypter
        sessionDecrypter = new SessionDecrypter(
        		sessionEncrypter.key.getSecretKey().getEncoded(), sessionEncrypter.iv1.getIV());
        
        HandshakeMessage serverForwardingInfo = new HandshakeMessage();
        serverForwardingInfo.putParameter("MessageType", "Session");
        serverForwardingInfo.putParameter("ServerHost", Handshake.serverHost);
        serverForwardingInfo.putParameter("ServerPort", String.valueOf(Handshake.serverPort));
        serverForwardingInfo.putParameter("SessionKey", sessionKeyEncoded);
        serverForwardingInfo.putParameter("SessionIV", sessionIvEncoded);
        
        serverForwardingInfo.send(clientSocket);
        clientSocket.close();

        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
           throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
           try {

               doHandshake();

            // TODO: Add encryption in ForwardServerClientThread!
               forwardThread = new ForwardServerClientThread(
            		   this.listenSocket, this.targetHost, this.targetPort, 
            		   this.sessionEncrypter, this.sessionDecrypter, true);
               forwardThread.start();
           } catch (IOException e) {
               throw e;
           }
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        try {
           srv.startForwardServer();
        } catch (Exception e) {
           e.printStackTrace();
        }
    }
 
}
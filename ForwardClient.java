/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
 
public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";
    public static final int TARGETHOST = 6789;
    public static final String FORWARDCLIENTCERT = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/user.pem";
    public static final String CACERTIFICATE = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/CA.pem";
    public static final String FORWARDCLIENTPRIVATEKEY = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/userPrivateKeypkcs8.der";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    private static MyCertificate forwardServerCertificate;
    private static SessionKey sessionKey;
    private static SessionEncrypter sessionEncrypter;
    private static SessionDecrypter sessionDecrypter;
    
    private static void doHandshake() throws IOException, CertificateException, 
    	NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, 
    	NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") 
        	+ ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), 
        		Integer.parseInt(arguments.get("handshakeport")));
        Logger.log("Now connected to " + socket.getRemoteSocketAddress());

		/* Handshake phase */

		// Send certificate to ForwardServer
//		MyCertificate userCertificate = 
//				new MyCertificate(new File(FORWARDCLIENTCERT));
		MyCertificate userCertificate = 
				new MyCertificate(new File(arguments.get("usercert")));
		byte[] userCertificateToBytes = 
				userCertificate.myCertificate.getEncoded();
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        String userCertificateToString = 
        		Base64.getEncoder().encodeToString(userCertificateToBytes);
        clientHello.putParameter("Certificate", userCertificateToString);
        clientHello.send(socket);
       
        // Receive ForwardServer's certificate
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);        
//        MyCertificate caCertificate = new MyCertificate(new File(CACERTIFICATE));
        MyCertificate caCertificate = new MyCertificate(new File(arguments.get("cacert")));
        
		// TODO: Remove. Just for testing
        VerifyMyCertificate verifyThisClientCert = new VerifyMyCertificate(caCertificate, userCertificate);
        if (verifyThisClientCert.verifyCertificate())
        	System.out.println("SERVER Cert is verified");
        else
        	System.out.println("SERVER Cert is verified");

        if(serverHello.getParameter("MessageType").equals("ServerHello")) {
        	
        	// Retrieve ForwardServer's certificate 
        	byte[] forwardServerCertificateBytes = 
        			Base64.getDecoder().
        			decode(serverHello.getParameter("Certificate"));
        	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        	InputStream in = new ByteArrayInputStream(forwardServerCertificateBytes);
        	X509Certificate forwardServerCertificateX = 
        			(X509Certificate)certFactory.generateCertificate(in);
        	Logger.log("ForwardServer's certificate" + 
        			forwardServerCertificateX.toString());
        	forwardServerCertificate = 
        			new MyCertificate(forwardServerCertificateX);
        	
        	// Verify certificate
			VerifyMyCertificate verifyMyCertificate = 
					new VerifyMyCertificate(caCertificate, forwardServerCertificate);
			if (verifyMyCertificate.verifyCertificate())
				System.out.println("ForwardServer's certificate verified");
			else
				System.out.println("Could not verify ForwardClient's certificate");
        }
        
        // Request forwarding 
        HandshakeMessage clientRequest = new HandshakeMessage();
        clientRequest.putParameter("MessageType", "Forward");
        clientRequest.putParameter("TargetHost", "localhost");
        clientRequest.putParameter("TargetPort", "6791");
//        clientRequest.putParameter("TargetHost", arguments.get("TargetHost"));
//        clientRequest.putParameter("TargetPort", arguments.get("TargetPort"));
        clientRequest.send(socket);
        
        // Receive forwarding host, port and session key
        HandshakeMessage serverForwardingInfo = new HandshakeMessage();
        serverForwardingInfo.recv(socket);
        if (serverForwardingInfo.getParameter("MessageType").equals("Session")) {
        	serverHost = serverForwardingInfo.getParameter("ServerHost");
        	serverPort = Integer.parseInt(serverForwardingInfo.getParameter(
        			"ServerPort"));
        	String sessionKeyEncryptedEncoded = serverForwardingInfo.getParameter(
        			"SessionKey");
//        	String sessionIv = serverForwardingInfo.getParameter("SessionIV");
        	String sessionIvEncryptedEncoded = serverForwardingInfo.getParameter("SessionIV");


        	// byte [] sessionKeyEncrypted = HandshakeCrypto.decrypt(sessionKeyEncryptedEncoded, );
        	
        	// Decode and decrypt session key and IV
        	byte [] sessionKeyEncryptedDecoded = Base64.getDecoder().decode(
        			sessionKeyEncryptedEncoded);
//        	PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(
//        			FORWARDCLIENTPRIVATEKEY);
        	PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
        	byte[] sessionKeyDecrypted = HandshakeCrypto.decrypt(
        			sessionKeyEncryptedDecoded, privateKey);
        	
        	byte [] sessionIvEncryptedDecoded = Base64.getDecoder().decode(
        			sessionIvEncryptedEncoded);
        	byte [] sessionIvDecrypted = HandshakeCrypto.decrypt(
        			sessionIvEncryptedDecoded, privateKey);
        	
        	sessionEncrypter = new SessionEncrypter(sessionKeyDecrypted, sessionIvDecrypted);
        	System.out.println("Received session key: " + sessionEncrypter.key.toString());
        	System.out.println("Received session key: " + sessionEncrypter.iv1.toString());
        	
        	// Generate session decrypter
        	sessionDecrypter = new SessionDecrypter(
        		sessionEncrypter.key.getSecretKey().getEncoded(), 
        		sessionEncrypter.iv1.getIV());
        	
//        	sessionKey = new SessionKey(sessionKeyDecrypted);
//        	System.out.println("Received session key: " + sessionKey);
        }
        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */
//        serverHost = Handshake.serverHost;
//        serverPort = Handshake.serverPort;        
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, CertificateException, 
    	InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, 
    	NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null); 
            /* Tell the user, so the user knows where to connect */ 
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);
           
            // TODO: Add encryption in ForwardServerClientThread!
            forwardThread = new ForwardServerClientThread(
            		clientSocket, serverHost, serverPort, 
            		sessionEncrypter, sessionDecrypter, false);
            forwardThread.start();
            
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     * @throws CertificateException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws NoSuchPaddingException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws InvalidAlgorithmParameterException 
     */
    public static void main(String[] args) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch(IOException e) {
           e.printStackTrace();
        }
    }
}
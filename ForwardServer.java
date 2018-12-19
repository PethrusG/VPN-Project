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
import java.security.cert.CertificateFactory;
 
public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String SERVERFORWARDERHOST = "localhost";
    public static final String SERVERFORWARDERPORT = "6789";
    public static final String PROGRAMNAME = "ForwardServer";
    public static final String CACERTIFICATE = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/CA.pem";
    public static final String FORWARDSERVERCERT = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/user.pem";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* TODO This is where the handshake should take place */
        // Receive and verify client's certificate
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);
        
        Logger.log("ForwardServer connected to: " + clientSocket.getRemoteSocketAddress());
        
        MyCertificate caCertificate = new MyCertificate(new File(CACERTIFICATE));
        if(clientHello.getParameter("messageType").equals("clientHello")) {
        	
        	// Retrieve ForwardClient's certificate from socket
        	byte[] forwardClientCertificateBytes = 
        			Base64.getDecoder().
        			decode(clientHello.getParameter("clientCertificate"));
        	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        	InputStream in = new ByteArrayInputStream(forwardClientCertificateBytes);
        	X509Certificate forwardClientCertificateX = 
        			(X509Certificate)certFactory.generateCertificate(in);
        	Logger.log("ForwardClient's certificate" + forwardClientCertificateX.toString());
        	MyCertificate forwardClientCertificate = new MyCertificate(forwardClientCertificateX);
        	
        	// Verify certificate
			VerifyMyCertificate verifyMyCertificate = new VerifyMyCertificate(caCertificate, forwardClientCertificate);
			if (verifyMyCertificate.verifyCertificate())
				System.out.println("ForwardClient's certificate verified");
			else
				System.out.println("Could not verify ForwardClient's certificate");
        }
        
        // Send certificate to ForwardClient
		MyCertificate userCertificate = 
				new MyCertificate(new File(FORWARDSERVERCERT));
		byte[] userCertificateToBytes = 
				userCertificate.myCertificate.getEncoded();
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.putParameter("messageType", "serverHello");
        String userCertificateToString = 
        		Base64.getEncoder().encodeToString(userCertificateToBytes);
        serverHello.putParameter("clientCertificate", userCertificateToString);
        serverHello.send(clientSocket);
        
        // Receive client request for target host & port
        HandshakeMessage clientRequest = new HandshakeMessage();
        clientRequest.recv(clientSocket);
        if(clientRequest.getParameter("messageType").equals("targetRequest")) {
        	targetHost = clientRequest.getParameter("targetHost");
        	targetPort = Integer.parseInt(clientRequest.getParameter("targetPort"));
        	Logger.log("From ClientServer: Target port is: " + targetPort + 
        			"\n Target host is: " + targetHost);
        }
        
        // Send forwarding host & port number to ForwardClient
        HandshakeMessage serverForwardingInfo = new HandshakeMessage();
        serverForwardingInfo.putParameter("messageType", "serverForwardingInfo");
        serverForwardingInfo.putParameter("serverForwarderHost", SERVERFORWARDERHOST);
        serverForwardingInfo.putParameter("serverForwarderPort", SERVERFORWARDERPORT);
        
        Logger.log("Before sending: messageType is: " 
        		+ serverForwardingInfo.getParameter("messageType"));
        Logger.log("Before sending: serverForwarderHost is: " 
        		+ serverForwardingInfo.getParameter("serverForwarderHost"));
        Logger.log("Before sending: serverForwarderPort is: " 
        		+ serverForwardingInfo.getParameter("serverForwarderPort"));
        
        serverForwardingInfo.send(clientSocket);
        	
        
        clientSocket.close();

        /*
         * Fake the handshake result with static parameters. 
         */

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
//        targetHost = Handshake.targetHost;
//        targetPort = Handshake.targetPort;        
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

               forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
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
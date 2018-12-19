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

 
import java.lang.AssertionError;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;
 
public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";
    public static final int TARGETHOST = 6789;
    public static final String FORWARDCLIENTCERT = "/home/pethrus/Desktop/År 4/P2/Internet Security/Project/user.pem";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    
    private static void doHandshake() throws IOException, CertificateException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") 
        	+ ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), 
        		Integer.parseInt(arguments.get("handshakeport")));
        Logger.log("Now connected to " + socket.getRemoteSocketAddress());
        /* TODO This is where the handshake should take place */

        // TODO 
        // 1. [X] First, just communicate targethost and targetport to ForwardServer
        //		  and receive serverhost and serverport answer. Test that it works.
        // 2. [ ] Then, add certificate verification. Test that it works.
        
        
		MyCertificate userCertificate = 
				new MyCertificate(new File(FORWARDCLIENTCERT));

		/* Handshake phase */

		byte[] userCertificateToBytes = 
				userCertificate.myCertificate.getEncoded();
//        String userCertificateToString = 
//        		Base64.getEncoder().encodeToString(userCertificateToBytes);

		// Send certificate to ForwardServer
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("messageType", "clientHello");
        String userCertificateToString = 
        		Base64.getEncoder().encodeToString(userCertificateToBytes);
        clientHello.putParameter("clientCertificate", userCertificateToString);
        clientHello.send(socket);
       
        // Receive and verify server's certificate
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);        
        // TODO: Verify server's certificat
        
        // Request forwarding 
        HandshakeMessage clientRequest = new HandshakeMessage();
        clientRequest.putParameter("messageType", "targetRequest");
        clientRequest.putParameter("targetHost", "localhost");
        clientRequest.putParameter("targetPort", "6791");
        clientRequest.send(socket);
        
        // Receive forwarding host & port
        HandshakeMessage serverForwardingInfo = new HandshakeMessage();
        serverForwardingInfo.recv(socket);
        if (serverForwardingInfo.getParameter("messageType").equals("serverForwardingInfo")) {
        	serverHost = serverForwardingInfo.getParameter("serverForwarderHost");
        	serverPort = Integer.parseInt(serverForwardingInfo.getParameter("serverForwarderPort"));
        }
//        socket.close();

        /* Session phase */ 
        
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
    static public void startForwardClient() throws IOException, CertificateException {

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
            
            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
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
     */
    public static void main(String[] args) throws CertificateException
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
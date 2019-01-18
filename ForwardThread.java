/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */
 
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.CipherOutputStream;
 
public class ForwardThread extends Thread
{
private static final int READ_BUFFER_SIZE = 8192;
private static String CIPHER = "/home/pethrus/Desktop/cipher.txt";
private static String PLAINOUTPUT = "/home/pethrus/Desktop/plainoutput.txt";
 
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
    CipherOutputStream mOutputStreamCipher = null;
    ForwardServerClientThread mParent = null;
    SessionEncrypter sessionEncrypter = null;
 
    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, 
    		InputStream aInputStream, OutputStream aOutputStream)
    {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
    }
 
    public ForwardThread(ForwardServerClientThread aParent, 
    		InputStream aInputStream, OutputStream aOutputStream, 
    		SessionEncrypter sessionEncrypter) throws FileNotFoundException
    {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
    }
    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run()
    {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        // TODO: Encrypt buffer
        try {
            while (true) {
                int bytesRead = mInputStream.read(buffer);
                if (bytesRead == -1)
                    break; // End of stream is reached --> exit the thread
                
                mOutputStream.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            // Read/write failed --> connection is broken --> exit the thread
        }
 
        // Notify parent thread that the connection is broken and forwarding should stop
        mParent.connectionBroken();
    } 
}
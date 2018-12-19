import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    //public static final String serverHost = "localhost";
    //public static final int serverPort = 4412;

    /* The final destination */
    //public static String targetHost = "localhost";
    //public static int targetPort = 6789;

    private static String targetHost;
    private int targetPort;

    private static String serverHost;
    private int serverPort;

    private SessionEncrypter encrypter;
    private SessionDecrypter decrypter;

    private X509Certificate clientCert;
    private X509Certificate serverCert;

    private CertificateFactory certFact = CertificateFactory.getInstance("X.509");

    Handshake() throws CertificateException {
    }

    void clientHello(String clientCertName, Socket socket) throws IOException, CertificateException {
        HandshakeMessage clientHello = new HandshakeMessage();
        InputStream inputStream = new FileInputStream(clientCertName);
        clientCert = (X509Certificate)certFact.generateCertificate(inputStream);
        String clientCertBase64EncodedString = Base64.getEncoder().encodeToString(clientCert.getEncoded());
        clientHello.putParameter("MessageType", "clientHello");
        clientHello.putParameter("Certificate", clientCertBase64EncodedString);
        System.out.println("Saying hello to server");
        clientHello.send(socket);
    }

    public void serverHello(String serverCertName, String CACertName, Socket socket) throws Exception {
        HandshakeMessage serverHello = new HandshakeMessage();
        HandshakeMessage fromClient = new HandshakeMessage();
        System.out.println("Waiting for client to say hello...");
        fromClient.recv(socket);
        if (fromClient.getParameter("MessageType").equals("clientHello")) {
            System.out.println("Received client hello! Saying hello back");

            //Get the client cert
            byte[] clientCertAsBytes = Base64.getDecoder().decode(fromClient.getParameter("Certificate"));
            InputStream clientCertInputStream = new ByteArrayInputStream(clientCertAsBytes);
            clientCert = (X509Certificate) certFact.generateCertificate(clientCertInputStream);

            //Make the CAcert
            InputStream CAcertStream = new FileInputStream(CACertName);
            X509Certificate CAcert = (X509Certificate) certFact.generateCertificate(CAcertStream);

            //Verify
            new VerifyCertificate(CAcert, clientCert).testValidity();

            //Make the serverCert
            InputStream serverCertStream = new FileInputStream(serverCertName);
            serverCert = (X509Certificate) certFact.generateCertificate(serverCertStream);

            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCert.getEncoded()));
            serverHello.send(socket);
        } else {
            System.out.println("Error: MessageType != clientHello");
            socket.close();
        }
    }

    public void forwardMessage(String targetHost, String targetPort, String CACertName, Socket socket) throws Exception {
        HandshakeMessage forwardMessage = new HandshakeMessage();
        HandshakeMessage fromServer = new HandshakeMessage();
        System.out.println("Awaiting hello from Server...");
        fromServer.recv(socket);

        if (fromServer.getParameter("MessageType").equals("ServerHello")) {

            System.out.println("Server said hello! Verifying certificates...");

            byte[] serverCertAsBytes = Base64.getDecoder().decode(fromServer.getParameter("Certificate"));
            InputStream serverCertStream = new ByteArrayInputStream(serverCertAsBytes);
            serverCert = (X509Certificate) certFact.generateCertificate(serverCertStream);
            InputStream CAcertInputStream = new FileInputStream(CACertName);
            X509Certificate CAcert = (X509Certificate) certFact.generateCertificate(CAcertInputStream);
            new VerifyCertificate(CAcert, serverCert).testValidity();

            System.out.println("Sending target information");

            forwardMessage.putParameter("MessageType", "Forward");
            forwardMessage.putParameter("TargetHost", targetHost);
            forwardMessage.putParameter("TargetPort", targetPort);
            forwardMessage.send(socket);
        } else {
            System.out.println("ERROR: MessageType != ServerHello");
            socket.close();
        }
    }

    public void sessionMessage(String serverHost, String serverPort, int keyLength, Socket socket) throws Exception {
        HandshakeMessage sessionMessage = new HandshakeMessage();
        HandshakeMessage fromClient = new HandshakeMessage();
        System.out.println("Awaiting session information from client...");
        fromClient.recv(socket);
        if (fromClient.getParameter("MessageType").equals("Forward")) {

            System.out.println("Session information received!");

            //Get target information
            targetHost = fromClient.getParameter("TargetHost");
            targetPort = Integer.parseInt(fromClient.getParameter("TargetPort"));

            //Create a symmetric key and a decrypter.
            IvParameterSpec IV = new IvParameterSpec(new SecureRandom().generateSeed(16));
            SessionKey sessionKey = new SessionKey(keyLength);
            decrypter = new SessionDecrypter(sessionKey,IV);

            //Encrypt the generated symmetric session key and IV with clients public key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, clientCert.getPublicKey());
            byte[] encryptedSessionKeyAsBytes = cipher.doFinal(sessionKey.encodeKey().getBytes());
            byte[] encryptedIVAsBytes = cipher.doFinal(IV.getIV());

            System.out.println("Sending final connection information");
            //Return the information for the next connection
            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKeyAsBytes));
            sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIVAsBytes));
            sessionMessage.putParameter("ServerHost", serverHost);
            sessionMessage.putParameter("ServerPort", serverPort);
            sessionMessage.send(socket);

        } else {
            System.out.println("Wrong type of parameter, expected Forward.");
            socket.close();
        }
    }

    public void finishHandshake(Socket socket, String clientPrivateKeyName) throws Exception {
        HandshakeMessage fromServer = new HandshakeMessage();
        System.out.println("Awaiting new socket information...");
        fromServer.recv(socket);
        if (fromServer.getParameter("MessageType").equals("Session")) {
            System.out.println("Received final socket! initializing encryption tools...");

            //Data socket
            serverHost = fromServer.getParameter("ServerHost");
            serverPort = Integer.parseInt(fromServer.getParameter("ServerPort"));

            //Decrypt session encryption info
            PrivateKey clientsPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(clientPrivateKeyName);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, clientsPrivateKey);
            byte[] receivedSessionKey = cipher.doFinal(Base64.getDecoder().decode(fromServer.getParameter("SessionKey")));
            byte[] receivedIV = cipher.doFinal(Base64.getDecoder().decode(fromServer.getParameter("SessionIV")));

            encrypter = new SessionEncrypter(new SessionKey(receivedSessionKey),receivedIV);

            System.out.println("Handshake complete!");
        } else {
            System.out.println("Error: MessageType != Session");
            socket.close();
        }
    }

    public String getTargetHost(){
        return targetHost;
    }

    public int getTargetPort(){
        return targetPort;
    }

    public String getServerHost(){
        return serverHost;
    }

    public int getServerPort(){
        return serverPort;
    }

    public SessionEncrypter getEncrypter(){
        return encrypter;
    }

    public SessionDecrypter getDecrypter(){
        return decrypter;
    }

}
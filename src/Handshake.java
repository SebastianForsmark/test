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

class Handshake {
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

    private X509Certificate storedClientCert;

    private CertificateFactory certFact = CertificateFactory.getInstance("X.509");

    Handshake() throws CertificateException {
    }

    void clientHello(String clientCertName, Socket socket) throws IOException, CertificateException {
        HandshakeMessage clientHello = new HandshakeMessage();
        X509Certificate clientCert = (X509Certificate)certFact.generateCertificate(new FileInputStream(clientCertName));
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", Base64.getEncoder().encodeToString(clientCert.getEncoded()));
        System.out.println("Saying hello to server");
        clientHello.send(socket);
    }

    void serverHello(String servCertName, String CACertName, Socket socket) throws Exception {
        HandshakeMessage serverHello = new HandshakeMessage();
        HandshakeMessage fromClient = new HandshakeMessage();
        System.out.println("Waiting for client to say hello...");
        fromClient.recv(socket);
        if (fromClient.getParameter("MessageType").equals("ClientHello")) {
            System.out.println("Received client hello! Verifying certificates...");

            //Retrieve client cert
            byte[] clientCertAsBytes = Base64.getDecoder().decode(fromClient.getParameter("Certificate"));
            InputStream clientCertInputStream = new ByteArrayInputStream(clientCertAsBytes);
            X509Certificate clientCert = (X509Certificate) certFact.generateCertificate(clientCertInputStream);

            //Simulate the server storing the client cert for use in sessionMessage().
            storedClientCert = clientCert;

            //Fetch the CA cert
            X509Certificate CAcert = (X509Certificate) certFact.generateCertificate(new FileInputStream(CACertName));

            //Verify the user with CA cert
            new VerifyCertificate(CAcert, clientCert).testValidity();

            //Make the serverCert
            X509Certificate serverCert = (X509Certificate) certFact.generateCertificate(new FileInputStream(servCertName));

            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCert.getEncoded()));
            serverHello.send(socket);
        } else {
            System.out.println("Error: MessageType != clientHello");
            socket.close();
        }
    }

    void forwardMessage(String targetHost, String targetPort, String CACertName, Socket socket) throws Exception {
        HandshakeMessage forwardMessage = new HandshakeMessage();
        HandshakeMessage fromServer = new HandshakeMessage();
        System.out.println("Awaiting hello from Server...");
        fromServer.recv(socket);

        if (fromServer.getParameter("MessageType").equals("ServerHello")) {

            System.out.println("Server said hello! Verifying certificates...");

            //Retrieve server cert
            byte[] servCertBytes = Base64.getDecoder().decode(fromServer.getParameter("Certificate"));
            X509Certificate servCert = (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(servCertBytes));

            //Fetch the CA cert
            X509Certificate CAcert = (X509Certificate) certFact.generateCertificate(new FileInputStream(CACertName));

            //Verify the server with the CA cert
            new VerifyCertificate(CAcert, servCert).testValidity();

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

    void sessionMessage(String serverHost, String serverPort, int keyLength, Socket socket) throws Exception {
        HandshakeMessage sessionMessage = new HandshakeMessage();
        HandshakeMessage fromClient = new HandshakeMessage();
        System.out.println("Awaiting target information from client...");
        fromClient.recv(socket);
        if (fromClient.getParameter("MessageType").equals("Forward")) {

            System.out.println("Target information received!");

            //Get target information
            targetHost = fromClient.getParameter("TargetHost");
            targetPort = Integer.parseInt(fromClient.getParameter("TargetPort"));

            //Create a symmetric key and a decrypter.
            IvParameterSpec IV = new IvParameterSpec(new SecureRandom().generateSeed(16));
            SessionKey sessionKey = new SessionKey(keyLength);
            decrypter = new SessionDecrypter(sessionKey,IV);

            //Encrypt the generated symmetric session key and IV with clients public key
            PublicKey pubKey = storedClientCert.getPublicKey();
            byte[] encryptedSessionKeyAsBytes = HandshakeCrypto.encrypt((sessionKey.encodeKey().getBytes()),pubKey);
            byte[] encryptedIVAsBytes = HandshakeCrypto.encrypt(IV.getIV(),pubKey);

            System.out.println("Sending session connection information");

            //Return the information for the next connection
            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKeyAsBytes));
            sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIVAsBytes));
            sessionMessage.putParameter("ServerHost", serverHost);
            sessionMessage.putParameter("ServerPort", serverPort);
            sessionMessage.send(socket);

        } else {
            System.out.println("ERROR: MessageType != Forward");
            socket.close();
        }
    }

    void finishHandshake(Socket socket, String clientPrivateKeyName) throws Exception {
        HandshakeMessage fromServer = new HandshakeMessage();
        System.out.println("Awaiting new socket information...");
        fromServer.recv(socket);
        if (fromServer.getParameter("MessageType").equals("Session")) {
            System.out.println("Received session socket! initializing encryption tools");

            //Session socket
            serverHost = fromServer.getParameter("ServerHost");
            serverPort = Integer.parseInt(fromServer.getParameter("ServerPort"));

            //Decrypt session encryption info
            PrivateKey privKey = HandshakeCrypto.getPrivateKeyFromKeyFile(clientPrivateKeyName);
            byte[] receivedSessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(fromServer.getParameter("SessionKey")),privKey);
            byte[] receivedIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(fromServer.getParameter("SessionIV")),privKey);

            encrypter = new SessionEncrypter(new SessionKey(receivedSessionKey),receivedIV);

            System.out.println("Handshake complete!");
        } else {
            System.out.println("Error: MessageType != Session");
            socket.close();
        }
    }

    String getTargetHost(){
        return targetHost;
    }

    int getTargetPort(){
        return targetPort;
    }

    String getServerHost(){
        return serverHost;
    }

    int getServerPort(){
        return serverPort;
    }

    SessionEncrypter getEncrypter(){
        return encrypter;
    }

    SessionDecrypter getDecrypter(){
        return decrypter;
    }

}
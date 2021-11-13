import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class Server {
    private final RSAKeyPair keyPair;
    private final Random rand;
    private final ServerSocket serverSocket;
    private Socket socket;
    private InputStream inbound;
    private OutputStream outbound;
    private BufferedReader reader;
    private PrintWriter writer;

    public Server() throws IOException {
        this.keyPair = RSA.generateRSAKeyPair();
        this.rand = new Random();
        serverSocket = new ServerSocket(Common.PORT);
    }

    public void run() throws IOException {
        boolean running = true;

        while (running) {
            socket = serverSocket.accept();
            inbound = socket.getInputStream();
            outbound = socket.getOutputStream();

            reader = new BufferedReader(new InputStreamReader(inbound, Common.CHARSET));
            writer = new PrintWriter(outbound, true, Common.CHARSET);

            String text = reader.readLine();
            System.out.println("Received Message: " + text);

            // Check if we got the correct setup message
            if (!text.equalsIgnoreCase("Hello")) {
                // got wrong greeting, abort
                socket.close();
                continue;
            }

            // Send RSA Public Key
            String rsaPublicKeyString = keyPair.getRSAPublicKey().toString();
            System.out.println("RSA: Sending Public Key: " + rsaPublicKeyString);
            writer.println(rsaPublicKeyString);

            // Receive encrypted Client ID
            // Decrypted using Server Private Key
            BigInteger clientID_encrypted = new BigInteger(reader.readLine());
            System.out.println("Received encrypted Client ID: " + clientID_encrypted);
            String clientID_decrypted = new String(RSA.decryptBytes(clientID_encrypted, keyPair.getRSAPrivateKey()).toByteArray(), Common.CHARSET);
            System.out.println("Decrypted Client ID: " + clientID_decrypted);

            // Send Server ID and Session ID
            // Signed using Server Private Key
            String serverID = Common.generateRandom16ByteID(rand);
            System.out.println("Sending Server ID: " + serverID);
            writer.println(serverID);
            BigInteger serverID_signature = RSA.generateSignature(new BigInteger(serverID.getBytes(Common.CHARSET)), keyPair.getRSAPrivateKey());
            System.out.println("Sending Server ID signature: " + serverID_signature);
            writer.println(serverID_signature);

            String sessionID = Common.generateRandom16ByteID(rand);
            System.out.println("Sending Session ID: " + sessionID);
            writer.println(sessionID);
            BigInteger sessionID_signature = RSA.generateSignature(new BigInteger(sessionID.getBytes(Common.CHARSET)), keyPair.getRSAPrivateKey());
            System.out.println("Sending Session ID signature: " + sessionID_signature);
            writer.println(sessionID_signature);

            // Begin DH-Exchange
            // We can choose any integer, but this is handy.
            // We generate random secrets on each connection to provide
            // forward secrecy and protection against man-in-the-middle attacks.
            BigInteger dhServerSecret = BigInteger.probablePrime(32, rand);
            BigInteger dhServerKey = Common.fastModularExponentiation(Common.DH_KEYPARAM_G, dhServerSecret,
                    Common.DH_KEYPARAM_P);
            System.out.println("DH: Sending Server Key: " + dhServerKey);
            writer.println(dhServerKey);

            BigInteger dhClientKey = new BigInteger(reader.readLine());
            System.out.println("DH: Received Client Key: " + dhClientKey);

            BigInteger sharedKey = Common.fastModularExponentiation(dhClientKey, dhServerSecret, Common.DH_KEYPARAM_P);
            System.out.println("DH: Computed Shared Key: " + sharedKey);

            reader.close();
            writer.close();
            socket.close();
        }

        serverSocket.close();
    }

    

    public static void main(String[] args) {
        try {
            new Server().run();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
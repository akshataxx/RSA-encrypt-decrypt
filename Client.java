import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Random;

public class Client {
    private final Random rand;
    private Socket socket;
    private InputStream inbound;
    private OutputStream outbound;
    private BufferedReader reader;
    private PrintWriter writer;

    public Client() {
        this.rand = new Random();
    }

    public void run() {
        try {
            socket = new Socket("localhost", Common.PORT);
            inbound = socket.getInputStream();
            outbound = socket.getOutputStream();

            reader = new BufferedReader(new InputStreamReader(inbound, Common.CHARSET));
            writer = new PrintWriter(outbound, true, Common.CHARSET);

            // The "Hello" setup message
            System.out.println("Sending Hello Message");
            writer.println("Hello");

            // Listen for reply (server's RSA public key)
            String rsaPublicKeyString = reader.readLine();
            String[] parts = rsaPublicKeyString.split(";");
            if (parts.length != 2) {
                System.err.println("Error receiving RSA public key.");
                cleanup();
                return;
            }
            RSAPublicKey rsaPublicKey = new RSAPublicKey(new BigInteger(parts[0]), new BigInteger(parts[1]));
            System.out.println("Received Server Public Key: " + rsaPublicKey.toString());

            // Send encrypted Client ID
            // Encrypted using Server Public Key
            String clientID_plain = Common.generateRandom16ByteID(rand);
            BigInteger clientID_encrypted = RSA.encryptBytes(new BigInteger(clientID_plain.getBytes(Common.CHARSET)), rsaPublicKey);
            System.out.println("Generated Client ID: " + clientID_plain);
            System.out.println("Sending encrypted Client ID: " + clientID_encrypted);
            writer.println(clientID_encrypted);

            // Receive Server ID and Session ID and verify signatures
            String serverID = reader.readLine();
            System.out.println("Received Server ID: " + serverID);
            BigInteger serverID_signature = new BigInteger(reader.readLine());
            System.out.println("Received Server ID signature: " + serverID_signature);
            boolean serverID_signature_okay = RSA.isSignatureOkay(new BigInteger(serverID.getBytes(Common.CHARSET)), serverID_signature,
                    rsaPublicKey);
            if (serverID_signature_okay)
                System.out.println("Server ID signature check successful.");
            else {
                System.err.println("Server ID signature check failed.");
            }

            String sessionID = reader.readLine();
            System.out.println("Received Session ID: " + sessionID);
            BigInteger sessionID_signature = new BigInteger(reader.readLine());
            System.out.println("Received Session ID signature: " + sessionID_signature);
            boolean sessionID_signature_okay = RSA.isSignatureOkay(new BigInteger(sessionID.getBytes(Common.CHARSET)), sessionID_signature,
                    rsaPublicKey);
            if (sessionID_signature_okay)
                System.out.println("Session ID signature check successful.");
            else {
                System.err.println("Session ID signature check failed.");
            }

            // DH-Exchange - more info in Server class
            BigInteger dhServerKey = new BigInteger(reader.readLine());
            System.out.println("DH: Received Server Key: " + dhServerKey);

            BigInteger dhClientSecret = BigInteger.probablePrime(32, rand);
            BigInteger dhClientKey = Common.fastModularExponentiation(Common.DH_KEYPARAM_G, dhClientSecret,
                    Common.DH_KEYPARAM_P);
            System.out.println("DH: Sending Client Key: " + dhClientKey);
            writer.println(dhClientKey);

            BigInteger sharedKey = Common.fastModularExponentiation(dhServerKey, dhClientSecret, Common.DH_KEYPARAM_P);
            System.out.println("DH: Computed Shared Key: " + sharedKey);

            cleanup();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void cleanup() {
        try {
            reader.close();
            writer.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Client().run();
    }
}
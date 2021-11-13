import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Common {
    public static final BigInteger DH_KEYPARAM_P = new BigInteger(
            "178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
    public static final BigInteger DH_KEYPARAM_G = new BigInteger(
            "174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");

    public static final Charset CHARSET = Charset.defaultCharset();
    public static final int PORT = 6543;

    public static BigInteger fastModularExponentiation(BigInteger base, BigInteger exponent, BigInteger mod) {
        BigInteger result = new BigInteger("1");

        while (exponent.compareTo(BigInteger.ZERO) == 1) {
            if (exponent.mod(BigInteger.TWO).compareTo(BigInteger.ONE) == 0) {
                result = result.multiply(base).mod(mod);
            }

            exponent = exponent.divide(BigInteger.TWO);
            base = base.multiply(base).mod(mod);
        }

        return result;
    }

    public static BigInteger getSHA256(BigInteger message) {
        try {
            return new BigInteger(MessageDigest.getInstance("SHA-256").digest(message.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void HMAC(byte[] key) {

        final int BLOCK_SIZE = 64;
        final int HASH_SIZE = 256;

        final byte I_PAD = 0x36;
        final byte O_PAD = 0x5C;

        byte[] ikey = new byte[BLOCK_SIZE];
        for (int i = 0; i < key.length; i++) {
            ikey[i] = (byte) (I_PAD ^ key[i]);
        }
        for (int i = key.length; i < BLOCK_SIZE; i++) {
            ikey[i] = I_PAD ^ 0;
        }

        byte[] okey = new byte[BLOCK_SIZE];
        for (int i = 0; i < key.length; i++) {
            okey[i] = (byte) (O_PAD ^ key[i]);
        }
        for (int i = key.length; i < BLOCK_SIZE; i++) {
            okey[i] = O_PAD ^ 0;
        }

        byte[] result = new byte[BLOCK_SIZE];

    }

    public static String generateRandom16ByteID(Random rand) {
        byte[] bytes = new byte[16];
        rand.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
import java.math.BigInteger;
import java.util.Random;

public class RSA {
    private static final BigInteger RSA_PUBLIC = new BigInteger("65537");

    private static final Random RAND = new Random();

    public static RSAKeyPair generateRSAKeyPair() {
        // Length of our RSA key in bits.
        final int length = 2048;

        // Select two large prime numbers.
        // Here we use 32 bits length.
        // Even though we use BigInteger's probablePrime function,
        // the probability for the two numbers to be primes is extremely high in this case.
        final BigInteger rsa_p = BigInteger.probablePrime(length, RAND);
        final BigInteger rsa_q = BigInteger.probablePrime(length, RAND);

        // Calculate m.
        BigInteger modulus = rsa_p.multiply(rsa_q);
        
        // See Wikipedia:
        // Compute λ(n), where λ is Carmichael's totient function.
        // Since n = pq, λ(n) = lcm(λ(p),λ(q)), and since p and q are prime, λ(p) = φ(p) = p − 1 and likewise λ(q) = q − 1.
        // Hence λ(n) = lcm(p − 1, q − 1).
        // The lcm may be calculated through the Euclidean algorithm, since lcm(a,b) = |ab|/gcd(a,b).
        final BigInteger lambda_n = lcm(rsa_p.subtract(BigInteger.ONE), rsa_q.subtract(BigInteger.ONE));
        
        // Calculate d. Mind that e is predefined in this excercise.
        BigInteger privateKey = RSA_PUBLIC.modInverse(lambda_n);

        return new RSAKeyPair(new RSAPublicKey(RSA_PUBLIC, modulus), new RSAPrivateKey(privateKey, modulus));
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return (a.multiply(b)).abs().divide(a.gcd(b));
    }

    public static BigInteger generateSignature(BigInteger message, RSAPrivateKey rsaPrivateKey) {
        BigInteger hash = Common.getSHA256(message);
        BigInteger signature = Common.fastModularExponentiation(hash, rsaPrivateKey.getPrivateKey(), rsaPrivateKey.getModulus());
        return signature;
    }

    public static boolean isSignatureOkay(BigInteger message, BigInteger signature, RSAPublicKey rsaPublicKey) {
        BigInteger hashIs = Common.getSHA256(message);
        BigInteger hashShould = Common.fastModularExponentiation(signature, rsaPublicKey.getPublicKey(), rsaPublicKey.getModulus());
        return hashIs.compareTo(hashShould) == 0;
    }

    public static BigInteger encryptBytes(BigInteger message, RSAPublicKey rsaPublicKey) {
        return Common.fastModularExponentiation(message, rsaPublicKey.getPublicKey(), rsaPublicKey.getModulus());
    }

    public static BigInteger decryptBytes(BigInteger cipher, RSAPrivateKey rsaPrivateKey) {
        return Common.fastModularExponentiation(cipher, rsaPrivateKey.getPrivateKey(), rsaPrivateKey.getModulus());
    }
}

import java.math.BigInteger;

public class RSAPublicKey {
    private final BigInteger publicKey;
    private final BigInteger modulus;

    public RSAPublicKey(BigInteger publicKey, BigInteger modulus) {
        this.publicKey = publicKey;
        this.modulus = modulus;
    }

    public BigInteger getPublicKey() { return this.publicKey; };
    public BigInteger getModulus() { return this.modulus; };

    @Override
    public String toString() {
        return getPublicKey() + ";" + getModulus();
    }
}

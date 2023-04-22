import java.math.BigInteger;

public class RSAPrivateKey {
    private final BigInteger privateKey;
    private final BigInteger modulus;

    public RSAPrivateKey(BigInteger privateKey, BigInteger modulus) {
        this.privateKey = privateKey;
        this.modulus = modulus;
    }

    public BigInteger getPrivateKey() { return this.privateKey; };
    public BigInteger getModulus() { return this.modulus; };

    @Override
    public String toString() {
        return getPrivateKey() + ";" + getModulus();
    }
}

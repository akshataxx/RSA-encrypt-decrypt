public class RSAKeyPair {
    private final RSAPublicKey rsaPublicKey;
    private final RSAPrivateKey rsaPrivateKey;

    public RSAKeyPair(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey) {
        this.rsaPublicKey = rsaPublicKey;
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public RSAPublicKey getRSAPublicKey() { return this.rsaPublicKey; };
    public RSAPrivateKey getRSAPrivateKey() { return this.rsaPrivateKey; };
}
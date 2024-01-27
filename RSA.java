import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger modulus;
    private BigInteger publicKey;
    private BigInteger privateKey;
    private final static SecureRandom random = new SecureRandom();

    public RSA(int bitLength) {
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        this.modulus = p.multiply(q);
        this.publicKey = new BigInteger("65537");
        this.privateKey = publicKey.modInverse(phi);
    }

    public BigInteger encrypt(String message) {
        byte[] bytes = message.getBytes();
        BigInteger messageBigInt = new BigInteger(bytes);
        return messageBigInt.modPow(publicKey, modulus);
    }

    public String decrypt(BigInteger encrypted) {
        BigInteger decryptedBigInt = encrypted.modPow(privateKey, modulus);
        byte[] bytes = decryptedBigInt.toByteArray();
        return new String(bytes);
    }

    public void setKeys(String publicKey, String privateKey) {
        this.publicKey = new BigInteger(publicKey);
        this.privateKey = new BigInteger(privateKey);
        this.modulus = BigInteger.ONE; // Dummy value to indicate keys are set
    }

    public void clearKeys() {
        this.modulus = null;
        this.publicKey = null;
        this.privateKey = null;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public String getPublicKey() {
        if (this.modulus != null && this.publicKey != null) {
            return this.publicKey.toString() + this.modulus.toString();
        } else {
            return "Public key not set";
        }
    }

    public String getPrivateKey() {
        if (this.modulus != null && this.privateKey != null) {
            return this.privateKey.toString() + this.modulus.toString();
        } else {
            return "Private key not set";
        }
    }

    @Override
    public String toString() {
        return "Public:\t" + this.publicKey +
                "Private:\t" + this.privateKey +
                "Modulus:\t" + this.modulus;
    }
}

//

import PrivateKey from "./PrivateKey";
import ZkpCommitment from "./ZkpCommitment";
import BigMath from "./BigMath";
import Signature from "./Signature";
import PublicKey from "./PublicKey";
import { BigInteger, default as bigInt } from "big-integer";

/**
 * An implementation of the Paillier crypto system extended with signing and zero-knowledge proofs.
 * https://en.wikipedia.org/wiki/Paillier_cryptosystem
 * https://www.cs.tau.ac.il/~fiat/crypt07/papers/Pai99pai.pdf
 * https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf
 * See the tests for how to use examples
 */
export default class Paillier {
    /**
     * Generates public and private key pair for the Paillier cryptosystem
     * @param {number} bits - Number of bits
     * @returns {[BigInteger, BigInteger]} The public and the private key
     */
    public static generateKeyPair(bits: number): [PublicKey, PrivateKey] {
        if (bits % 8 > 0 || bits < 160) throw new RangeError("Key must be at least 160 bits");

        // It is very unlikely the rng to return same number twice however we add this check
        let p: BigInteger, q: BigInteger, n: BigInteger;
        // Choose two large primes p and q randomly and independently of each other
        // such that gcd(p * q, (p - 1)(q - 1)) = 1
        // This property is assured if both primes are of equivalent length
        do {
            do {
                // TODO: Use method to find strong primes
                p = BigMath.generateRandomPrime(bits / 2);
                q = BigMath.generateRandomPrime(bits / 2);
            } while (p.equals(q));

            // Compute RSA modulus n = pq
            n = p.multiply(q);
        } while (n.bitLength().toJSNumber() != bits);

        // Carmichael’s function lambda = lcm(𝑝 − 1, 𝑞 − 1)
        let lambda: BigInteger = p
            .minus(bigInt.one)
            .multiply(q.minus(bigInt.one))
            .divide(bigInt.gcd(p.minus(bigInt.one), q.minus(bigInt.one)));

        // Select generator g where g ∈ Z∗n^2
        // TODO: Try alternatively g = (an + 1)*b^n mod n^2 where a, b are randoms in Z*n
        let g: BigInteger = n.plus(1); // Shortcut

        // mu = (L(g^lambda mod n^2))^-1 mod n
        // L(u) = (u - 1) / n
        // u = g^lambda mod n^2
        let u: BigInteger = g.modPow(lambda, n.square());
        let u2: BigInteger = u.minus(bigInt.one).divide(n);
        let mu: BigInteger = u2.modInv(n);

        return [new PublicKey(n, g), new PrivateKey(lambda, mu)];
    }

    /**
     * Encrypts a message (BigInteger) and generates a zero-knowledge proof from a list of valid messages
     * @param {BigInteger} m - message to encrypt
     * @param {BigInteger[]} valid - list of valid messages
     * @param {PublicKey} pub - public key to encrypt with
     * @returns {[BigInteger, ZkpCommitment]} The encrypted message and the ZKP commitment
     */
    public static encryptWithZkp(m: BigInteger, valid: BigInteger[], pub: PublicKey): [BigInteger, ZkpCommitment] {
        let [c, r] = this.encryptWithoutR(m, pub);
        let commitment = this.createZkp(m, c, r, valid, pub);
        return [c, commitment];
    }

    /**
     * Encrypts a message (BigInteger)
     * @param {BigInteger} m - message to encrypt
     * @param {PublicKey} pub - public key to encrypt with
     * @returns {BigInteger} The encrypted message
     */
    public static encrypt(m: BigInteger, pub: PublicKey): BigInteger {
        let [c, r] = this.encryptWithoutR(m, pub);
        return c;
    }

    /**
     * Creates a zero-knowledge proof commitment
     * @param {BigInteger} m - plain message
     * @param {BigInteger} c - encrypted message
     * @param {BigInteger} r - multiplier r
     * @param {BigInteger[]} valid - list of valid messages
     * @param {PublicKey} pub - public key to encrypt with
     * @returns {ZkpCommitment} ZKP commitment
     */
    public static createZkp(
        m: BigInteger,
        c: BigInteger,
        r: BigInteger,
        valid: BigInteger[],
        pub: PublicKey,
    ): ZkpCommitment {
        let commitment = new ZkpCommitment(valid.length);

        // Choose random ω ∈ Z∗n
        let omega: BigInteger;
        do {
            omega = BigMath.generateCoprime(pub.n, pub.n.bitLength().toJSNumber());
        } while (omega.greaterOrEquals(pub.n)); // This should always be false and is just a precaution
        let mk: number = -1;

        // For reach valid message m[i]
        for (let i: number = 0; i < valid.length; i++) {
            // u[i] = c / g^m[i] mod n^2
            let mi: BigInteger = valid[i];
            let gmi: BigInteger = pub.g.modPow(mi, pub.nSquared);
            let ui: BigInteger = c.multiply(gmi.modInv(pub.nSquared)).mod(pub.nSquared);

            if (mi.notEquals(m)) {
                // e1,e2,e3, ...,ek ∈ 2^b < min(p, q)
                let ei = BigMath.generateRandom(pub.n.bitLength().toJSNumber() / 2 - 1); // bit length of p and q = pubkey length / 2
                commitment.e[i] = ei;

                // z1, z2, z3, ..., zk ∈ Z∗n
                let zi = BigMath.generateCoprime(pub.n, pub.n.bitLength().toJSNumber() - 1);
                commitment.z[i] = zi;

                // a1, a2, a3, ..., ak where a[i] = z[i]^n / u[i]^e[i] mod n^2
                let zin: BigInteger = zi.modPow(pub.n, pub.nSquared);
                let uiei: BigInteger = ui.modPow(ei, pub.nSquared);
                let ai: BigInteger = zin.multiply(uiei.modInv(pub.nSquared)).mod(pub.nSquared);
                commitment.a[i] = ai;
            } else {
                // For m[i] = m, we calculate a[i] as follows
                // a[i] = ω^n mod n^2
                let ai = omega.modPow(pub.n, pub.nSquared);
                commitment.a[i] = ai;

                mk = i;
            }
        }

        if (mk < 0) throw new Error("Message m isn't included in the list of valid messages");

        // Non-interactive version
        let challenge: BigInteger = BigMath.bigIntHashFromBigIntArray(commitment.a);

        // modulo equal to the length of the hash - 256 bits
        let hashMod: BigInteger = bigInt(2).pow(256);

        // The prover now calculates z[k] and e[k] for m[k] = m as follows
        let esum: BigInteger = commitment.e
            .reduce((prev: BigInteger, cur: BigInteger) => {
                return prev.add(cur);
            })
            .mod(hashMod);
        // e[k] = e_challange - sum(e[i])
        let ek = BigMath.positiveMod(challenge.minus(esum), hashMod);

        commitment.e[mk] = ek;
        // z[k] = ω ∗ r^e[k] mod n
        let zk: BigInteger = omega.multiply(r.modPow(ek, pub.n)).mod(pub.n);
        commitment.z[mk] = zk;

        commitment.makeStringifyToBase64();

        return commitment;
    }

    /**
     * Verifies the validity of a zero-knowledge proof
     * @param {BigInteger} c - encrypted message
     * @param {BigInteger[]} valid - list of valid messages
     * @param {ZkpCommitment} commitment - The ZKP commitment
     * @param {PublicKey} pub - public key to encrypt with
     * @returns {boolean} true if correct
     */
    public static verifyZkp(
        c: BigInteger,
        valid: Array<BigInteger>,
        commitment: ZkpCommitment,
        pub: PublicKey,
    ): boolean {
        if (valid.length * 3 != commitment.a.length + commitment.e.length + commitment.z.length)
            throw new RangeError("Invalid commitment or valid messages");

        // sum(e[k]) = challenger mod 2^2b
        let challenger: BigInteger = BigMath.bigIntHashFromBigIntArray(commitment.a);
        let hashMod: BigInteger = bigInt(2).pow(256);
        let esum: BigInteger = commitment.e
            .reduce((prev: BigInteger, cur: BigInteger) => {
                return prev.add(cur);
            })
            .mod(hashMod);
        // If this fails, then the prover did not follow the rules or attempted to cheat
        if (esum.notEquals(challenger)) return false;

        // For reach valid message m[i]
        for (let i = 0; i < valid.length; i++) {
            // u[i] = c / g^m[i] mod n^2
            let mi: BigInteger = valid[i];
            let gmi: BigInteger = pub.g.modPow(mi, pub.nSquared);
            let ui: BigInteger = c.multiply(gmi.modInv(pub.nSquared)).mod(pub.nSquared);

            // z[i]^n = a[i] * u[i]^e[i] nod n^2
            let zi: BigInteger = commitment.z[i];
            let ai: BigInteger = commitment.a[i];
            let ei: BigInteger = commitment.e[i];
            let zin: BigInteger = zi.modPow(pub.n, pub.nSquared);
            let uiei: BigInteger = ui.modPow(ei, pub.nSquared);
            let aiuiei: BigInteger = ai.multiply(uiei).mod(pub.nSquared);
            // If this fails, then the prover did not follow the rules or attempted to cheat
            if (zin.notEquals(aiuiei)) return false;
        }

        return true;
    }

    /**
     * Decrypts an encrypted message and returns the plain message
     * @param {BigInteger} c - encrypted message
     * @param {PublicKey} pub - public key to encrypt with
     * @returns {BigInteger} Plain message
     */
    public static decrypt(c: BigInteger, pub: PublicKey, priv: PrivateKey): BigInteger {
        // The ciphertext c < n ^ 2
        if (c.greaterOrEquals(pub.nSquared)) throw new Error("ciphertext must be less than modulo n^2");

        // m = L(c^lambda mod n^2) * mu mod n
        // L(u) = (u - 1) / n
        let u: BigInteger = c.modPow(priv.lambda, pub.nSquared);
        let m: BigInteger = u.minus(bigInt.one).divide(pub.n).multiply(priv.mu).mod(pub.n);
        return m;
    }

    /**
     * Digitally signs a message
     * @param {BigInteger} m - plain message
     * @param {PublicKey} pub - public key
     * @param {PrivateKey} priv - private key
     * @returns {Signature} The signature for the message
     */
    public static createSignature(m: BigInteger, pub: PublicKey, priv: PrivateKey): Signature {
        // Calculate h(m) = hash of message m
        let h = BigMath.bigIntHashFromBigInt(m);

        // s1 = (L(h(m)^lambda mod n^2) / L(g^lambda mod n^2)) mod n
        let s1Num = h.modPow(priv.lambda, pub.nSquared).minus(bigInt(1)).divide(pub.n);
        let s1Den = priv.mu;
        let s1 = s1Num.multiply(s1Den).mod(pub.n);

        // s2 = ((h(m)g^-s1)^(1/n mod lambda)) mod n
        let invN = pub.n.modInv(priv.lambda);
        let test = pub.g.modPow(s1, pub.n);
        let invG = test.modInv(pub.n);
        let s2 = h.multiply(invG).modPow(invN, pub.n);

        return new Signature(s1, s2);
    }

    /**
     * Verifies the validity of a signature
     * @param {BigInteger} m - plain message
     * @param {Signature} sig - signature
     * @param {PublicKey} pub - public key
     * @returns {boolean} True if valid
     */
    public static verifySignature(m: BigInteger, sig: Signature, pub: PublicKey): boolean {
        // h(m) ?= g^s1 * s2^n | mod n^2
        let h = BigMath.bigIntHashFromBigInt(m);
        let gs1 = pub.g.modPow(sig.s1, pub.nSquared);
        let s2n = sig.s2.modPow(pub.n, pub.nSquared);
        let hm = gs1.multiply(s2n).mod(pub.nSquared);
        return hm.equals(h);
    }

    /**
     * Adds two encrypted messages and returns the encrypted sum
     * @param {BigInteger} em1 - encrypted message 1
     * @param {BigInteger} em2 - encrypted message 2
     * @param {PublicKey} pub - public key
     * @returns {BigInteger} Encrypted sum = em1 + em2
     */
    public static addEncrypted(em1: BigInteger, em2: BigInteger, pub: PublicKey): BigInteger {
        // d(e(m1) * e(m2) mod n^2) = m1 + m2 mod n
        return em1.multiply(em2).mod(pub.nSquared);
    }

    /**
     * Adds a scalar to an encrypted message and returns the encrypted sum
     * @param {BigInteger} em - encrypted message
     * @param {BigInteger} k - scalar
     * @param {PublicKey} pub - public key
     * @returns {BigInteger} Encrypted sum = em + k
     */
    public static addScalar(em: BigInteger, k: BigInteger, pub: PublicKey): BigInteger {
        // d(e(m) * g^k mod n^2) = m + k mod n
        return em.multiply(pub.g.modPow(k, pub.nSquared)).mod(pub.nSquared);
    }

    /**
     * Multiplies an encrypted message with a scalar and returns the encrypted product
     * @param {BigInteger} em - encrypted message
     * @param {BigInteger} k - scalar
     * @param {PublicKey} pub - public key
     * @returns {BigInteger} Encrypted product = em * k
     */
    public static mulScalar(em: BigInteger, k: BigInteger, pub: PublicKey): BigInteger {
        // d(e(m)^k mod n^2) = k * m mod n
        return em.modPow(k, pub.nSquared);
    }

    /**
     * Encrypts a message with a random multiplier
     */
    private static encryptWithoutR(m: BigInteger, pub: PublicKey): [BigInteger, BigInteger] {
        // Find a random r where 𝑟 ∈ 𝑍𝑛*2
        let r: BigInteger = bigInt.zero;
        do {
            r = BigMath.generateCoprime(pub.n, pub.n.bitLength().toJSNumber());
        } while (r.greaterOrEquals(pub.n)); // This should always be false and is just a precaution
        return this.encryptWithR(m, pub, r);
    }

    /**
     * Encrypts a message with a specified multiplier
     */
    private static encryptWithR(m: BigInteger, pub: PublicKey, r: BigInteger): [BigInteger, BigInteger] {
        // Plaintext is m where m < n
        if (m.greaterOrEquals(pub.n)) throw Error("plaintext must be less than modulo n");

        // Let ciphertext c = g^m * r^n mod n^2
        let gm = pub.n.multiply(m).add(bigInt.one).mod(pub.nSquared);
        let rn = r.modPow(pub.n, pub.nSquared);
        let c = gm.multiply(rn).mod(pub.nSquared);

        BigMath.makeStringifyToBase64(c);

        return [c, r];
    }
}

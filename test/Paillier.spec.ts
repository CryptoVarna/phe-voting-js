import "mocha";
import { assert, expect } from "chai";
import { BigInteger, default as bigInt } from "big-integer";

import PublicKey from "../src/PublicKey";
import PrivateKey from "../src/PrivateKey";
import Paillier from "../src/Paillier";
import ZkpCommitment from "../src/ZkpCommitment";

describe("Testing Paillier cryptosystem", () => {
    it("should generate correct key pairs", () => {
        for (let bits = 256; bits < 1024; bits *= 2) {
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(bits);
            expect(pub.n.bitLength().toJSNumber()).to.be.greaterThan(bits - 10);
            expect(priv.lambda.bitLength().toJSNumber()).to.be.greaterThan(0);
            expect(priv.mu.bitLength().toJSNumber()).to.be.greaterThan(0);
        }
    });

    [
        { keySize: 256, input: "0" },
        { keySize: 160, input: "1" },
        { keySize: 160, input: "8572057275" },
        { keySize: 256, input: "95477148500050043847142" },
        { keySize: 512, input: "93875198749187950505012983050847247412455461" },
    ].forEach((test) => {
        it(`should encrypt and decrypt correctly: ${test.input}`, () => {
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(test.keySize);
            let m = bigInt(test.input);
            let c = Paillier.encrypt(m, pub);
            let d = Paillier.decrypt(c, pub, priv);
            assert(d.equals(m));
        });
    });

    it(`should add 2 encrypted numbers`, () => {
        let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(256);
        let sum = bigInt.zero;
        let encryptedSum = Paillier.encrypt(bigInt.zero, pub);

        for (let i = 0; i < 100; i++) {
            let n = bigInt(2).pow(i);
            sum = sum.plus(n);
            let c = Paillier.encrypt(n, pub);
            encryptedSum = Paillier.addEncrypted(encryptedSum, c, pub);
        }

        let decryptedSum = Paillier.decrypt(encryptedSum, pub, priv);
        assert(decryptedSum.equals(sum));
    });

    it(`should add encrypted number and a scalar`, () => {
        let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(256);
        let sum = bigInt.zero;
        let encryptedSum = Paillier.encrypt(bigInt.zero, pub);

        for (let i = 0; i < 100; i++) {
            let n = bigInt(2).pow(i);
            sum = sum.plus(n);
            encryptedSum = Paillier.addScalar(encryptedSum, n, pub);
        }

        let decryptedSum = Paillier.decrypt(encryptedSum, pub, priv);
        assert(decryptedSum.equals(sum));
    });

    it(`should multiply encrypted number with a scalar`, () => {
        let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(256);
        let prod = bigInt.one;
        let encryptedProd = Paillier.encrypt(bigInt.one, pub);

        for (let i = 0; i < 20; i++) {
            let n = bigInt(2).pow(i);
            prod = prod.multiply(n);
            encryptedProd = Paillier.mulScalar(encryptedProd, n, pub);
        }

        let decryptedProd = Paillier.decrypt(encryptedProd, pub, priv);
        assert(decryptedProd.equals(prod));
    });

    [
        { keySize: 256, input: bigInt(0), valid: [bigInt(0), bigInt(1), bigInt(2), bigInt(3)] },
        { keySize: 256, input: bigInt(1), valid: [bigInt(1), bigInt(2), bigInt(3)] },
        { keySize: 256, input: bigInt(2).pow(255), valid: [bigInt(2).pow(16), bigInt(2).pow(64), bigInt(2).pow(255)] },
        {
            keySize: 512,
            input: bigInt(2).pow(300),
            valid: [bigInt(2).pow(256), bigInt(2).pow(512), bigInt(2).pow(300)],
        },
    ].forEach((test) => {
        it(`should create ZKP and verify with valid input`, () => {
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(test.keySize);
            let [c, commitment]: [BigInteger, ZkpCommitment] = Paillier.encryptWithZkp(test.input, test.valid, pub);
            let result = Paillier.verifyZkp(c, test.valid, commitment, pub);
            expect(result).to.be.true;
        });
    });

    [
        { keySize: 256, input: bigInt(1), cheatInput: bigInt(4), valid: [bigInt(1), bigInt(2), bigInt(3)] },
        { keySize: 256, input: bigInt(1), cheatInput: bigInt(1), valid: [bigInt(1), bigInt(2), bigInt(3)] },
        {
            keySize: 256,
            input: bigInt(2).pow(128),
            cheatInput: bigInt(2).pow(129),
            valid: [bigInt(2).pow(16), bigInt(2).pow(128), bigInt(2).pow(255)],
        },
    ].forEach((test) => {
        it(`should create ZKP and NOT verify it with invalid input`, () => {
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(test.keySize);
            let [c, commitment]: [BigInteger, ZkpCommitment] = Paillier.encryptWithZkp(test.input, test.valid, pub);
            let cheatC = Paillier.encrypt(test.cheatInput, pub);
            let result = Paillier.verifyZkp(cheatC, test.valid, commitment, pub);
            expect(result).to.be.false;
        });
    });

    it(`should NOT create ZKP when input is not in the valid set`, () => {
        let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(256);
        let input = bigInt(4);
        let valid = [bigInt(1), bigInt(2), bigInt(3)];
        let shouldThrow = () => {
            Paillier.encryptWithZkp(input, valid, pub);
        };
        assert.throws(shouldThrow, Error);
    });

    [
        { keySize: 256, input: "0" },
        { keySize: 160, input: "1" },
        { keySize: 160, input: "8572057275" },
        { keySize: 256, input: "95477148500050043847142" },
        { keySize: 512, input: "93875198749187950505012983050847247412455461" },
    ].forEach((test) => {
        it(`should sign and verify signature correctly: ${test.input}`, () => {
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(test.keySize);
            let m = bigInt(test.input);
            let sig = Paillier.createSignature(m, pub, priv);
            let v = Paillier.verifySignature(m, sig, pub);
            expect(v).to.be.true;
        });
    });
});

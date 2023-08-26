import "mocha";
import { assert, expect } from "chai";
import { default as bigInt } from "big-integer";

import VoteEncoder from "../src/VoteEncoder";
import PublicKey from "../src/PublicKey";
import PrivateKey from "../src/PrivateKey";
import Paillier from "../src/Paillier";

describe("Testing VoteEncoder", () => {
    [
        { choice: 0, numChoices: 3, bitsPerChoice: 8, expected: "1" },
        { choice: 1, numChoices: 3, bitsPerChoice: 8, expected: "256" },
        { choice: 2, numChoices: 3, bitsPerChoice: 8, expected: "65536" },
    ].forEach((test) => {
        it(`should encode (W/O GROUPS) single choice ${test.choice} to ${test.expected}`, () => {
            let encoded = VoteEncoder.encodeSingle(test.choice, test.numChoices, test.bitsPerChoice);
            expect(encoded.equals(bigInt(test.expected))).to.be.true;
            let decoded = VoteEncoder.decode(encoded, test.numChoices, test.bitsPerChoice);
            expect(decoded[test.choice]).to.equals(1);
        });
    });

    [
        { choice: 0, numChoices: 2, bin: 0, numBins: 3, bitsPerChoice: 8, expected: "1" },
        { choice: 1, numChoices: 2, bin: 0, numBins: 3, bitsPerChoice: 8, expected: "256" },
        { choice: 0, numChoices: 2, bin: 1, numBins: 3, bitsPerChoice: 8, expected: "65536" },
        { choice: 1, numChoices: 2, bin: 1, numBins: 3, bitsPerChoice: 8, expected: "16777216" },
    ].forEach((test) => {
        it(`should encode (W/ GROUPS) single choice ${test.choice} to ${test.expected}`, () => {
            let encoded = VoteEncoder.encodeSingle(
                test.choice,
                test.numChoices,
                test.bitsPerChoice,
                test.bin,
                test.numBins,
            );
            expect(encoded.equals(bigInt(test.expected))).to.be.true;
            let decoded = VoteEncoder.decodeGroups(encoded, test.numChoices, test.bitsPerChoice, test.numBins);
            expect(decoded[test.bin][test.choice]).to.equals(1);
        });
    });

    [
        { choice: 2, numChoices: 2, bin: 0, numBins: 2, bitsPerChoice: 8 },
        { choice: 1, numChoices: 2, bin: 2, numBins: 2, bitsPerChoice: 8 },
        { choice: 1, numChoices: 20, bin: 1, numBins: 20, bitsPerChoice: 1 },
    ].forEach((test) => {
        it(`should NOT encode (W/ GROUPS) single choice with bad arguments`, () => {
            let shouldThrow = () => {
                VoteEncoder.encodeSingle(test.choice, test.numChoices, test.bitsPerChoice, test.bin, test.numBins);
            };
            assert.throws(shouldThrow);
        });
    });

    [
        { choices: [0], numChoices: 2, bitsPerChoice: 8, expected: "1" },
        { choices: [0, 1], numChoices: 2, bitsPerChoice: 8, expected: "257" },
        { choices: [0, 1, 2], numChoices: 3, bitsPerChoice: 8, expected: "65793" },
    ].forEach((test) => {
        it(`should encode (W/O GROUPS) multiple choice`, () => {
            let encoded = VoteEncoder.еncodeMultiple(test.choices, test.numChoices, test.bitsPerChoice);
            expect(encoded.equals(bigInt(test.expected))).to.be.true;
            let decoded = VoteEncoder.decode(encoded, test.numChoices, test.bitsPerChoice);
            for (let choice of test.choices) expect(decoded[choice]).to.equals(1);
        });
    });

    [
        { choices: [0], numChoices: 2, bin: 0, numBins: 2, bitsPerChoice: 8, expected: "1" },
        { choices: [0, 1], numChoices: 2, bin: 1, numBins: 2, bitsPerChoice: 8, expected: "16842752" },
        { choices: [0, 1, 2], numChoices: 3, bin: 1, numBins: 2, bitsPerChoice: 8, expected: "1103823372288" },
    ].forEach((test) => {
        it(`should encode (W/O GROUPS) multiple choice`, () => {
            let encoded = VoteEncoder.еncodeMultiple(
                test.choices,
                test.numChoices,
                test.bitsPerChoice,
                test.bin,
                test.numBins,
            );
            expect(encoded.equals(bigInt(test.expected))).to.be.true;
            let decoded = VoteEncoder.decodeGroups(encoded, test.numChoices, test.bitsPerChoice, test.numBins);
            for (let choice of test.choices) expect(decoded[test.bin][choice]).to.equals(1);
        });
    });

    [
        { numChoices: 10, numBins: 10, bitsPerChoice: 8, expected: 800 },
        { numChoices: 2, numBins: 2, bitsPerChoice: 32, expected: 128 },
        { numChoices: 0, numBins: 0, bitsPerChoice: 0, expected: 0 },
        { numChoices: 20, numBins: 20, bitsPerChoice: 32, expected: 12800 },
    ].forEach((test) => {
        it(`should calculate the number of bits needed to encode all votes`, () => {
            let maxVotes = VoteEncoder.getTotalVotesBits(test.numChoices, test.numBins, test.bitsPerChoice);
            expect(maxVotes).to.equals(test.expected);
        });
    });

    [
        { numChoices: 5, numVotes: 100, keySize: 160, bitsPerChoice: 8 },
        { numChoices: 2, numVotes: 100, keySize: 256, bitsPerChoice: 8 },
        { numChoices: 10, numVotes: 200, keySize: 256, bitsPerChoice: 8 },
    ].forEach((test) => {
        it(`should encrypt aggregation (W/O GROUPS)`, () => {
            // Key generation
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(test.keySize);

            let validVotes = VoteEncoder.getSingleChoicePermutations(test.numChoices, test.bitsPerChoice);
            let realVotes = new Array<number>(validVotes.length).fill(0);

            let sum = bigInt.zero;
            let encryptedSum = Paillier.encrypt(bigInt.zero, pub);

            for (let i = 0; i < test.numVotes; i++) {
                // Choose random vote
                let vote = Math.floor(Math.random() * test.numChoices);
                // Encode vote
                let encodedVote = VoteEncoder.encodeSingle(vote, test.numChoices, test.bitsPerChoice);
                // Encrypt vote
                let [encryptedVote, commitment] = Paillier.encryptWithZkp(encodedVote, validVotes, pub);

                // Check vote validity
                let valid = Paillier.verifyZkp(encryptedVote, validVotes, commitment, pub);
                expect(valid).to.be.true;
                // Aggregate votes
                realVotes[vote]++;
                encryptedSum = Paillier.addEncrypted(encryptedSum, encryptedVote, pub);
            }

            let decryptedSum = Paillier.decrypt(encryptedSum, pub, priv);
            let decodedSum = VoteEncoder.decode(decryptedSum, test.numChoices, test.bitsPerChoice);
            for (let i = 0; i < decodedSum.length; i++) assert.equal(decodedSum[i], realVotes[i]);
        });
    });

    [
        { numChoices: 5, numVotes: 100, bin: 0, numBins: 2, keySize: 160, bitsPerChoice: 8 },
        { numChoices: 2, numVotes: 100, bin: 1, numBins: 2, keySize: 256, bitsPerChoice: 8 },
    ].forEach((test) => {
        it(`should encrypt aggregation (W/ GROUPS)`, () => {
            if (VoteEncoder.getTotalVotesBits(test.numChoices, test.numBins, test.bitsPerChoice) > test.keySize)
                throw new RangeError("Insufficient key size");

            // Key generation
            let [pub, priv]: [PublicKey, PrivateKey] = Paillier.generateKeyPair(test.keySize);

            let validVotes = VoteEncoder.getSingleChoicePermutations(test.numChoices, test.bitsPerChoice, test.numBins);
            let realVotes = new Array<number>(validVotes.length).fill(0);

            let encryptedSum = Paillier.encrypt(bigInt.zero, pub);

            for (let i = 0; i < test.numVotes; i++) {
                // Choose random vote
                let vote = Math.floor(Math.random() * test.numChoices);
                // Encode vote
                let encodedVote = VoteEncoder.encodeSingle(
                    vote,
                    test.numChoices,
                    test.bitsPerChoice,
                    test.bin,
                    test.numBins,
                );
                // Encrypt vote
                let [encryptedVote, commitment] = Paillier.encryptWithZkp(encodedVote, validVotes, pub);

                // Check vote validity
                let valid = Paillier.verifyZkp(encryptedVote, validVotes, commitment, pub);
                expect(valid).to.be.true;
                // Aggregate votes
                realVotes[vote]++;
                encryptedSum = Paillier.addEncrypted(encryptedSum, encryptedVote, pub);
            }

            let decryptedSum = Paillier.decrypt(encryptedSum, pub, priv);
            let decodedSum = VoteEncoder.decodeGroups(decryptedSum, test.numChoices, test.bitsPerChoice, test.numBins);
            for (let i = 0; i < decodedSum.length; i++) assert.equal(decodedSum[test.bin][i], realVotes[i]);
        });
    });
});

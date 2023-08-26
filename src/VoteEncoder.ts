import { BigInteger, default as bigInt } from "big-integer";

/**
 * Voting encoder utilizing Paillier partial homomorphic crypto system
 * See the tests for how to use examples
 */
export default class VoteEncoder {
    /**
     * Encodes a single choice vote into a BigInteger.
     * Choices from multiple votes can be grouped into a single BigInteger by separating into bins.
     * @param {number} choice - The choice - 0...n
     * @param {number} numChoices - What is the total number of the choices
     * @param {number} bitsPerChoice - How many bits we will reserve per choice. 2^bitPerChoice must be less than numChoices
     * @param {number} [bin=0] - The index of the bin for the grouping
     * @param {number} [numBins=0] - The total number of bins for grouping
     * @returns {BigInteger} The encoded integer
     */
    public static encodeSingle(
        choice: number,
        numChoices: number,
        bitsPerChoice: number,
        bin: number = 0,
        numBins: number = 0,
    ): BigInteger {
        if (choice >= numChoices || numChoices < 2) throw new RangeError("Invlid choices");
        if (numBins > 0 && bin >= numBins) throw new RangeError("Invalid bins");
        if (bitsPerChoice < 2) throw new RangeError("bitsPerChoice must be at least 2");
        if (2 << (bitsPerChoice - 1) >= Number.MAX_SAFE_INTEGER)
            throw new RangeError("Too big voting space, exceeds max int");
        return bigInt.one.shiftLeft(bitsPerChoice * (bin * numChoices + choice));
    }

    /**
     * Encodes multiple choices into a BigInteger.
     * Choices from multiple votes can be grouped into a single BigInteger by separating into bins.
     * @param {number[]} choices - The choices - e.g. [0, 2]
     * @param {number} numChoices - What is the total number of the choices
     * @param {number} bitsPerChoice - The sum of the two numbers
     * @param {number} [bin=0] - The index of the bin for the grouping
     * @param {number} [numBins=0] - The total number of bins for grouping
     * @returns {BigInteger} The encoded integer
     */
    public static еncodeMultiple(
        choices: number[],
        numChoices: number,
        bitsPerChoice: number,
        bin: number = 0,
        numBins: number = 0,
    ): BigInteger {
        let result = bigInt.zero;
        for (let choice of choices) {
            result = result.plus(VoteEncoder.encodeSingle(choice, numChoices, bitsPerChoice, bin, numBins));
        }
        return result;
    }

    /**
     * Decodes grouped votes. The result is an array of all groups(bins) containing all votes.
     * @param {BigInteger} encoded - The encoded big integer
     * @param {number} numChoices - What is the total number of the choices
     * @param {number} bitsPerChoice - The sum of the two numbers
     * @param {number} numBins - The total number of bins for grouping
     * @returns {Array<Array<number>>} List of all groups with all the votes for each choice
     */
    public static decodeGroups(
        encoded: BigInteger,
        numChoices: number,
        bitsPerChoice: number,
        numBins: number,
    ): Array<Array<number>> {
        if (2 << (bitsPerChoice - 1) >= Number.MAX_SAFE_INTEGER)
            throw new RangeError("Too big voting space, exceeds max int");

        let result: Array<Array<number>> = new Array<Array<number>>(numBins);
        for (let bin = 0; bin < numBins; bin++) {
            result[bin] = new Array(numChoices);
            for (let choice = 0; choice < numChoices; choice++) {
                let answer = encoded
                    .shiftRight((choice + bin * numChoices) * bitsPerChoice)
                    .and((1 << (bitsPerChoice - 1)) - 1);
                result[bin][choice] = answer.toJSNumber();
            }
        }
        return result;
    }

    /**
     * Decodes non-grouped votes. The result is an array of all votes.
     * @param {BigInteger} encoded - The encoded big integer
     * @param {number} numChoices - What is the total number of the choices
     * @param {number} bitsPerChoice - The sum of the two numbers
     * @returns {number[]} List of all the votes for each choice
     */
    public static decode(encoded: BigInteger, numChoices: number, bitsPerChoice: number): number[] {
        if (2 << (bitsPerChoice - 1) >= Number.MAX_SAFE_INTEGER)
            throw new RangeError("Too big voting space, exceeds max int");

        let result: number[] = new Array<number>(numChoices);
        for (let choice = 0; choice < numChoices; choice++) {
            let answer = encoded.shiftRight(choice * bitsPerChoice).and((1 << (bitsPerChoice - 1)) - 1);
            result[choice] = answer.toJSNumber();
        }
        return result;
    }

    /**
     * Calculates the maximum bits required to encode a number of choices grouped into number of bins.
     * @param {number} numChoices - What is the total number of the choices
     * * @param {number} numBins - The total number of bins for grouping
     * @param {number} bitsPerChoice - The sum of the two numbers
     * @returns {number} Number of bits
     */
    public static getTotalVotesBits(numChoices: number, numBins: number, bitsPerChoice: number): number {
        if (numChoices <= 0 || bitsPerChoice <= 0) return 0;
        if (numBins <= 0) numBins = 1;
        return numChoices * numBins * bitsPerChoice;
    }

    /**
     * Generates all permutations of encoded votes (single choice) grouped in bins
     * @param {number} numChoices - What is the total number of the choices
     * @param {number} bitsPerChoice - The sum of the two numbers
     * @param {number} numBins - The total number of bins for grouping
     * @returns {Array<BigInteger>} Permutations
     */
    public static getSingleChoicePermutations(
        numChoices: number,
        bitsPerChoice: number,
        numBins: number = 0,
    ): Array<BigInteger> {
        if (numChoices < 2) throw new RangeError("Invalid choices");

        let list = new Array<BigInteger>();
        let bin = 0;
        do {
            for (let choice = 0; choice < numChoices; choice++) {
                let vote = VoteEncoder.encodeSingle(choice, numChoices, bitsPerChoice, bin, numBins);
                list.push(vote);
            }
        } while (++bin < numBins);
        return list;
    }
}

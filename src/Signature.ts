import { BigInteger } from "big-integer";

/**
 * A signature for Paillier cryptosystem
 */
export default class Signature {
    public s1: BigInteger;
    public s2: BigInteger;

    constructor(s1: BigInteger, s2: BigInteger) {
        this.s1 = s1;
        this.s2 = s2;
    }
}

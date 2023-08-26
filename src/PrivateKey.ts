import { BigInteger } from "big-integer";

/**
 * A private key in the Paillier system
 */
export default class PrivateKey {
    public lambda: BigInteger;
    public mu: BigInteger;

    constructor(lambda: BigInteger, mu: BigInteger) {
        this.lambda = lambda;
        this.mu = mu;
    }
}

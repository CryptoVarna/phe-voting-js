import { BigInteger } from "big-integer";
import BigMath from "./BigMath";

/**
 * A public key in the Paillier system
 */
export default class PublicKey {
    public n: BigInteger;
    public nSquared: BigInteger;
    public g: BigInteger;

    constructor(n: BigInteger, g: BigInteger) {
        this.n = n;
        BigMath.makeStringifyToBase64(this.n);
        this.g = g;
        BigMath.makeStringifyToBase64(this.g);
        this.nSquared = n.square();
    }

    public static from(o: any): PublicKey {
        return new PublicKey(BigMath.base64ToBigInt(o.n), BigMath.base64ToBigInt(o.g));
    }
}

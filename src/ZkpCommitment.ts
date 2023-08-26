import { BigInteger } from "big-integer";
import BigMath from "./BigMath";

/**
 * A strucuture for zero-knowledge proof commitment
 */
export default class ZkpCommitment {
    public a: BigInteger[];
    public e: BigInteger[];
    public z: BigInteger[];

    constructor(capacity: number = 0) {
        this.a = new Array<BigInteger>(capacity);
        this.e = new Array<BigInteger>(capacity);
        this.z = new Array<BigInteger>(capacity);
        this.makeStringifyToBase64();
    }

    public makeStringifyToBase64() {
        this.a.forEach((value) => BigMath.makeStringifyToBase64(value));
        this.e.forEach((value) => BigMath.makeStringifyToBase64(value));
        this.z.forEach((value) => BigMath.makeStringifyToBase64(value));
    }

    public static create(a: BigInteger[], e: BigInteger[], z: BigInteger[]) {
        let c = new ZkpCommitment(a.length);
        c.a = a;
        c.e = e;
        c.z = z;
        c.makeStringifyToBase64();
        return c;
    }

    private static fromArray(a: any): Array<BigInteger> {
        let result = new Array<BigInteger>();
        for (let v of a) {
            result.push(BigMath.base64ToBigInt(v));
        }
        return result;
    }

    public static from(o: any): ZkpCommitment {
        return this.create(this.fromArray(o.a), this.fromArray(o.e), this.fromArray(o.z));
    }
}

import { recoverPersonalSignature, personalSign } from '@metamask/eth-sig-util';
import * as _ from 'lodash';

export class Metamask {
    // --------------------------------------------------------------------------
    //
    //  Static Methods
    //
    // --------------------------------------------------------------------------

    public static ALGORITHM = 'KeccakMetamask';

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public static sign(message: string, privateKey: string): string {
        return personalSign({ data: message, privateKey: Buffer.from(privateKey, 'hex') });
    }

    public static verify(message: string, signature: string, address: string): boolean {
        let recovered = recoverPersonalSignature({ data: message, signature: signature });
        return recovered.toUpperCase() === address.toUpperCase();
    }
}

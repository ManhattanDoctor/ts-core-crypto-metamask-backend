import { ITransportCommand, ISignature, TransportCryptoManager } from '@ts-core/common';
import { recoverPersonalSignature, personalSign } from '@metamask/eth-sig-util';
import * as _ from 'lodash';

export class TransportCryptoManagerMetamaskBackend extends TransportCryptoManager {
    // --------------------------------------------------------------------------
    //
    //  Static Methods
    //
    // --------------------------------------------------------------------------

    public static ALGORITHM = 'Ed25519Metamask';

    // --------------------------------------------------------------------------
    //
    //  Constructor
    //
    // --------------------------------------------------------------------------

    constructor(protected wallet: any) {
        super();
    }

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------


    public async sign<U>(command: ITransportCommand<U>, nonce: string, privateKey: string): Promise<string> {
        return personalSign({ data: this.toString(command, nonce), privateKey: Buffer.from(privateKey, 'hex') });
    }

    public async verify<U>(command: ITransportCommand<U>, signature: ISignature): Promise<boolean> {
        let address = recoverPersonalSignature({ data: this.toString(command, signature.nonce), signature: signature.value });
        return address.toUpperCase() === signature.publicKey.toUpperCase();
    }

    // --------------------------------------------------------------------------
    //
    //  Public Properties
    //
    // --------------------------------------------------------------------------

    public get algorithm(): string {
        return TransportCryptoManagerMetamaskBackend.ALGORITHM;
    }
}
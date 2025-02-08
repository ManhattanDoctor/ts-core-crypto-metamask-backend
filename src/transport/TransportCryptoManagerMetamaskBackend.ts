import { ITransportCommand, ISignature, TransportCryptoManager } from '@ts-core/common';
import { Metamask } from '../Metamask';
import * as _ from 'lodash';

export class TransportCryptoManagerMetamaskBackend extends TransportCryptoManager {
    // --------------------------------------------------------------------------
    //
    //  Static Methods
    //
    // --------------------------------------------------------------------------

    public static ALGORITHM = Metamask.ALGORITHM;

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public async sign<U>(command: ITransportCommand<U>, nonce: string, privateKey: string): Promise<string> {
        return Metamask.sign(this.toSign(command, nonce), privateKey);
    }

    public async verify<U>(command: ITransportCommand<U>, signature: ISignature): Promise<boolean> {
        return Metamask.verify(this.toSign(command, signature.nonce), signature.value, signature.publicKey);
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
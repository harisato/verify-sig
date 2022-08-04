import { ethToEvmos } from '@tharsis/address-converter';
import * as ethUtils from 'ethereumjs-util';
import { toBech32 } from '@cosmjs/encoding';
import * as BytesUtils from '@ethersproject/bytes';
import { serializeSignDoc, StdSignDoc } from '@cosmjs/amino';
import { HdPath, Keccak256, keccak256, Secp256k1, Slip10RawIndex } from '@cosmjs/crypto';
import { Wallet } from '@ethersproject/wallet';

export function makeEvmoshubPath(a: number): HdPath {
  return [Slip10RawIndex.hardened(44), Slip10RawIndex.hardened(60), Slip10RawIndex.hardened(0), Slip10RawIndex.normal(0), Slip10RawIndex.normal(a)];
}

export async function evmosSignAmino(msg: StdSignDoc, privKey: Uint8Array, pubkey: Uint8Array) {
  const serializeDoc = serializeSignDoc(msg);

  // Use ether js to sign Ethereum tx
  const ethWallet = new Wallet(privKey);
  const signature = await ethWallet._signingKey().signDigest(keccak256(serializeDoc));
  const splitSignature = BytesUtils.splitSignature(signature);
  /** example splitSignature
   * {
      r: '0x31ae3dcafccd310d043f0f4938d59494402eba4dc45fcd93ba4ec82887c08555',
      s: '0x7d41dd788d460986a4d3547eebd584df658787f18d66b167b96a592fc2fb56dd',
      _vs: '0xfd41dd788d460986a4d3547eebd584df658787f18d66b167b96a592fc2fb56dd',
      recoveryParam: 1,
      v: 28,
      yParityAndS: '0xfd41dd788d460986a4d3547eebd584df658787f18d66b167b96a592fc2fb56dd',
      compact: '0x31ae3dcafccd310d043f0f4938d59494402eba4dc45fcd93ba4ec82887c08555fd41dd788d460986a4d3547eebd584df658787f18d66b167b96a592fc2fb56dd'
    }
   */
  return splitSignature;
}

export function getEvmosAddr(pubkey: Uint8Array, prefix = 'evmos') {
  const pubKeyUncompressed = Secp256k1.uncompressPubkey(pubkey);
  const hash = new Keccak256(pubKeyUncompressed.slice(1)).digest();
  const lastTwentyBytes = hash.slice(-20);

  return toBech32(prefix, lastTwentyBytes);
}

export async function evmosVerifySig(v: number, r: string, s: string, msg: StdSignDoc, expectEvmosAddr: string) {
  const pub = ethUtils.ecrecover(ethUtils.toBuffer(keccak256(serializeSignDoc(msg))), v, ethUtils.toBuffer(r), ethUtils.toBuffer(s));
  const addrBuf = ethUtils.pubToAddress(pub);
  const addr = ethUtils.bufferToHex(addrBuf);
  const evmosAddr = ethToEvmos(addr);

  if (evmosAddr !== expectEvmosAddr) {
    throw new Error(`Expected ${expectEvmosAddr} but got ${evmosAddr}`);
  } else {
    console.log('Signature verification success');
  }
}

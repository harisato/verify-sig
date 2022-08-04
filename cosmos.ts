import { fromBase64 } from '@cosmjs/encoding';
import { encodeSecp256k1Pubkey, encodeSecp256k1Signature, pubkeyToAddress, serializeSignDoc, StdSignDoc } from '@cosmjs/amino';
import { Secp256k1, Secp256k1Signature, sha256 } from '@cosmjs/crypto';

export function getCosmosAddr(pubkey: Uint8Array, prefix: string) {
  const pubkeyFormated = encodeSecp256k1Pubkey(pubkey);
  return pubkeyToAddress(pubkeyFormated, prefix);
}

export async function cosmosSignAmino(msg: StdSignDoc, privKey: Uint8Array, pubkey: Uint8Array) {
  const serializeDoc = serializeSignDoc(msg);
  const message = sha256(serializeDoc);
  const signature = await Secp256k1.createSignature(message, privKey);
  const signatureBytes = new Uint8Array([...signature.r(32), ...signature.s(32)]);
  return {
    signed: msg,
    signature: encodeSecp256k1Signature(pubkey, signatureBytes),
  };
}

export async function cosmosVerifySig(pubkey: Uint8Array, msg: StdSignDoc, signature: string) {
  const resultVerify = await Secp256k1.verifySignature(Secp256k1Signature.fromFixedLength(fromBase64(signature)), sha256(serializeSignDoc(msg)), pubkey);
  if (!resultVerify) {
    throw new Error('Signature verification failed');
  } else {
    console.log('Signature verification success');
  }
}

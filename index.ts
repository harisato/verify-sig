import * as dotenv from 'dotenv';
dotenv.config();
import * as evmos from './evmos';
import * as cosmos from './cosmos';
import { makeCosmoshubPath, Secp256k1HdWalletOptions, StdSignDoc } from '@cosmjs/amino';
import { Bip39, EnglishMnemonic, HdPath, Secp256k1, Secp256k1Keypair, Slip10, Slip10Curve } from '@cosmjs/crypto';
const defaultOptions: Secp256k1HdWalletOptions = {
  bip39Password: '',
  hdPaths: [makeCosmoshubPath(0)],
  prefix: 'cosmos',
};
async function defaultKeys() {
  const defaultMnemonic = process.env.MNEMONIC || '';
  const mnemonicChecked = new EnglishMnemonic(defaultMnemonic);
  const seed = await Bip39.mnemonicToSeed(mnemonicChecked);

  return { mnemonicChecked, seed };
}

const main = async () => {
  const { mnemonicChecked, seed } = await defaultKeys();

  // AURA
  verifyAura(mnemonicChecked, seed);

  // EVMOS
  verifyEvmos(mnemonicChecked, seed);
};

async function verifyAura(mnemonicChecked: EnglishMnemonic, seed: Uint8Array) {
  // load hdwallet
  const [{ pubkey, privkey }] = await newSecp256k1HdWallet(mnemonicChecked, { seed: seed });

  const expectAddr = process.env.EXPECT_AURA_ADDR || '';
  const signer = cosmos.getCosmosAddr(pubkey, 'aura');
  if (signer !== expectAddr) {
    throw new Error(`Expected ${expectAddr} but got ${signer}`);
  }

  const timeStamp = new Date().getTime();
  const data = Buffer.from(`${timeStamp}`).toString('base64');
  const msg: StdSignDoc = createSignMessageByData(signer, data);

  const { signature } = await cosmos.cosmosSignAmino(msg, privkey, pubkey);
  await cosmos.cosmosVerifySig(pubkey, msg, signature.signature);
}

async function verifyEvmos(mnemonicChecked: EnglishMnemonic, seed: Uint8Array) {
  const [{ pubkey, privkey }] = await newSecp256k1HdWallet(mnemonicChecked, { seed: seed, hdPaths: [evmos.makeEvmoshubPath(0)] });
  const expectEvmosAddr = process.env.EXPECT_EVMOS_ADDR;
  const signerEvmos = evmos.getEvmosAddr(pubkey);
  if (signerEvmos !== expectEvmosAddr) {
    throw new Error(`Expected ${expectEvmosAddr} but got ${signerEvmos}`);
  }

  const timeStamp = new Date().getTime();
  const data = Buffer.from(`${timeStamp}`).toString('base64');
  const msg: StdSignDoc = createSignMessageByData(signerEvmos, data);
  const { r, s, v } = await evmos.evmosSignAmino(msg, privkey, pubkey);
  await evmos.evmosVerifySig(v, r, s, msg, expectEvmosAddr);
}

function createSignMessageByData(address: string, data: string) {
  const signDoc = {
    chain_id: '',
    account_number: '0',
    sequence: '0',
    fee: {
      gas: '0',
      amount: [],
    },
    msgs: [
      {
        type: 'sign/MsgSignData',
        value: {
          signer: address,
          data: Buffer.from(data, 'utf8').toString('base64'),
        },
      },
    ],
    memo: '',
  };
  return signDoc;
}

async function getKeyPair(hdPath: HdPath, seed: Uint8Array): Promise<Secp256k1Keypair> {
  const { privkey } = Slip10.derivePath(Slip10Curve.Secp256k1, seed, hdPath);
  const { pubkey } = await Secp256k1.makeKeypair(privkey);
  return {
    privkey: privkey,
    pubkey: Secp256k1.compressPubkey(pubkey),
  };
}

interface Secp256k1HdWalletConstructorOptions extends Partial<Secp256k1HdWalletOptions> {
  readonly seed: Uint8Array;
}
async function newSecp256k1HdWallet(mnemonic: EnglishMnemonic, options: Secp256k1HdWalletConstructorOptions) {
  const hdPaths = options.hdPaths ?? defaultOptions.hdPaths;
  const prefix = defaultOptions.prefix;
  const seed = options.seed;
  const accounts = hdPaths.map((hdPath) => ({
    hdPath: hdPath,
    prefix,
  }));
  return Promise.all(
    accounts.map(async ({ hdPath, prefix }) => {
      const { privkey, pubkey } = await getKeyPair(hdPath, seed);
      return {
        algo: 'secp256k1' as const,
        privkey: privkey,
        pubkey: pubkey,
      };
    })
  );
}

main();

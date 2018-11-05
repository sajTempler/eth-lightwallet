const CryptoJS = require('crypto-js');
const Transaction = require('ethereumjs-tx');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1'); // todo verify
const bitcore = require('bitcore-lib');
const Random = bitcore.crypto.Random;
const Hash = bitcore.crypto.Hash;
const Mnemonic = require('bitcore-mnemonic');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const scrypt = require('scrypt-async');

const encryption = require('./encryption');
const signing = require('./signing');

function strip0x(input) {
    if (typeof(input) !== 'string') {
        return input;
    }
    else if (input.length >= 2 && input.slice(0, 2) === '0x') {
        return input.slice(2);
    }
    else {
        return input;
    }
}

function add0x(input) {
    if (typeof(input) !== 'string') {
        return input;
    }
    else if (input.length < 2 || input.slice(0, 2) !== '0x') {
        return '0x' + input;
    }
    else {
        return input;
    }
}

function leftPadString(stringToPad, padChar, length) {

    let repreatedPadChar = '';
    for (let i = 0; i < length; i++) {
        repreatedPadChar += padChar;
    }

    return ((repreatedPadChar + stringToPad).slice(-length));
}

function nacl_encodeHex(msgUInt8Arr) {
    const msgBase64 = naclUtil.encodeBase64(msgUInt8Arr);
    return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
    const msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
    return naclUtil.decodeBase64(msgBase64);
}

const KeyStore = function () {
};

KeyStore.prototype.init = function (mnemonic, pwDerivedKey, hdPathString, salt) {

    this.salt = salt;
    this.hdPathString = hdPathString;
    this.encSeed = undefined;
    this.encHdRootPriv = undefined;
    this.version = 3;
    this.hdIndex = 0;
    this.encPrivKeys = {};
    this.addresses = [];

    if ((typeof pwDerivedKey !== 'undefined') && (typeof mnemonic !== 'undefined')) {
        const words = mnemonic.split(' ');
        if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH) || words.length !== 12) {
            throw new Error('KeyStore: Invalid mnemonic');
        }

        // Pad the seed to length 120 before encrypting
        const paddedSeed = leftPadString(mnemonic, ' ', 120);
        this.encSeed = encryptString(paddedSeed, pwDerivedKey);

        // hdRoot is the relative root from which we derive the keys using
        // generateNewAddress(). The derived keys are then
        // `hdRoot/hdIndex`.

        const hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
        const hdRootKey = new bitcore.HDPrivateKey(hdRoot);
        const hdPathKey = hdRootKey.derive(hdPathString).xprivkey;
        this.encHdRootPriv = encryptString(hdPathKey, pwDerivedKey);
    }
};

KeyStore.createVault = function (opts, cb) {

    // Default hdPathString
    if (!('hdPathString' in opts)) {
        const err = new Error("Keystore: Must include hdPathString in createVault inputs. Suggested alternatives are m/0'/0'/0' for previous lightwallet default, or m/44'/60'/0'/0 for BIP44 (used by Jaxx & MetaMask)")
        return cb(err)
    }

    if (!('seedPhrase' in opts)) {
        const err = new Error('Keystore: Must include seedPhrase in createVault inputs.')
        return cb(err)
    }

    if (!('salt' in opts)) {
        opts.salt = generateSalt(32);
    }

    KeyStore.deriveKeyFromPasswordAndSalt(opts.password, opts.salt, function (err, pwDerivedKey) {
        if (err) return cb(err);

        const ks = new KeyStore();
        ks.init(opts.seedPhrase, pwDerivedKey, opts.hdPathString, opts.salt);

        cb(null, ks);
    });
};

KeyStore.generateSalt = generateSalt;

function generateSalt(byteCount) {
    return bitcore.crypto.Random.getRandomBuffer(byteCount || 32).toString('base64');
}

KeyStore.prototype.isDerivedKeyCorrect = function (pwDerivedKey) {
    try {
        const paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);
        return !!paddedSeed;
    } catch (err) {
        return false;
    }
};

function encryptString(string, pwDerivedKey) {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encObj = nacl.secretbox(naclUtil.decodeUTF8(string), nonce, pwDerivedKey);
    return {
        'encStr': naclUtil.encodeBase64(encObj),
        'nonce': naclUtil.encodeBase64(nonce)
    };
}

KeyStore._encryptString = encryptString;

KeyStore._decryptString = function (encryptedStr, pwDerivedKey) {

    const secretbox = naclUtil.decodeBase64(encryptedStr.encStr);
    const nonce = naclUtil.decodeBase64(encryptedStr.nonce);

    const decryptedStr = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

    if (!decryptedStr) {
        return null;
    }

    return naclUtil.encodeUTF8(decryptedStr);
};

KeyStore._encryptKey = function (privKey, pwDerivedKey) {

    const privKeyArray = nacl_decodeHex(privKey);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

    let encKey = nacl.secretbox(privKeyArray, nonce, pwDerivedKey);
    encKey = { 'key': naclUtil.encodeBase64(encKey), 'nonce': naclUtil.encodeBase64(nonce) };

    return encKey;
};

KeyStore._decryptKey = function (encryptedKey, pwDerivedKey) {

    const secretbox = naclUtil.decodeBase64(encryptedKey.key);
    const nonce = naclUtil.decodeBase64(encryptedKey.nonce);
    const decryptedKey = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

    if (decryptedKey === undefined) {
        throw new Error("Decryption failed!");
    }

    return nacl_encodeHex(decryptedKey);
};

KeyStore._computeAddressFromPrivKey = function (privKey) {
    const keyPair = ec.genKeyPair();
    keyPair._importPrivate(privKey, 'hex');
    const compact = false;
    const pubKey = keyPair.getPublic(compact, 'hex').slice(2);
    const pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey);
    const hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 });
    const address = hash.toString(CryptoJS.enc.Hex).slice(24);

    return address;
};

KeyStore._computePubkeyFromPrivKey = function (privKey, curve) {

    if (curve !== 'curve25519') {
        throw new Error('KeyStore._computePubkeyFromPrivKey: Only "curve25519" supported.');
    }

    const privKeyBase64 = (new Buffer(privKey, 'hex')).toString('base64');
    const privKeyUInt8Array = naclUtil.decodeBase64(privKeyBase64);
    const pubKey = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey;
    const pubKeyBase64 = naclUtil.encodeBase64(pubKey);
    const pubKeyHex = (new Buffer(pubKeyBase64, 'base64')).toString('hex');

    return pubKeyHex;
};


KeyStore.prototype._generatePrivKeys = function (pwDerivedKey, n) {

    if (!this.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const hdRoot = KeyStore._decryptString(this.encHdRootPriv, pwDerivedKey);

    if (hdRoot.length === 0) {
        throw new Error('Provided password derived key is wrong');
    }

    const keys = [];
    for (let i = 0; i < n; i++) {
        const hdprivkey = new bitcore.HDPrivateKey(hdRoot).derive(this.hdIndex++);
        const privkeyBuf = hdprivkey.privateKey.toBuffer();

        let privkeyHex = privkeyBuf.toString('hex');
        if (privkeyBuf.length < 16) {
            // Way too small key, something must have gone wrong
            // Halt and catch fire
            throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
        }
        else if (privkeyBuf.length < 32) {
            // Pad private key if too short
            // bitcore has a bug where it sometimes returns
            // truncated keys
            privkeyHex = leftPadString(privkeyBuf.toString('hex'), '0', 64);
        }
        else if (privkeyBuf.length > 32) {
            throw new Error('Private key larger than 32 bytes. Aborting!');
        }

        const encPrivKey = KeyStore._encryptKey(privkeyHex, pwDerivedKey);
        keys[i] = {
            privKey: privkeyHex,
            encPrivKey: encPrivKey
        }
    }

    return keys;
};


// This function is tested using the test vectors here:
// http://www.di-mgt.com.au/sha_testvectors.html
KeyStore._concatAndSha256 = function (entropyBuf0, entropyBuf1) {

    const totalEnt = Buffer.concat([entropyBuf0, entropyBuf1]);
    if (totalEnt.length !== entropyBuf0.length + entropyBuf1.length) {
        throw new Error('generateRandomSeed: Logic error! Concatenation of entropy sources failed.')
    }

    const hashedEnt = Hash.sha256(totalEnt);

    return hashedEnt;
}

// External static functions


// Generates a random seed. If the optional string
// extraEntropy is set, a random set of entropy
// is created, then concatenated with extraEntropy
// and hashed to produce the entropy that gives the seed.
// Thus if extraEntropy comes from a high-entropy source
// (like dice) it can give some protection from a bad RNG.
// If extraEntropy is not set, the random number generator
// is used directly.

KeyStore.generateRandomSeed = function (extraEntropy) {

    let seed = '';
    if (extraEntropy === undefined) {
        seed = new Mnemonic(Mnemonic.Words.ENGLISH);
    }
    else if (typeof extraEntropy === 'string') {
        const entBuf = new Buffer(extraEntropy);
        const randBuf = Random.getRandomBuffer(256 / 8);
        const hashedEnt = this._concatAndSha256(randBuf, entBuf).slice(0, 128 / 8);
        seed = new Mnemonic(hashedEnt, Mnemonic.Words.ENGLISH);
    }
    else {
        throw new Error('generateRandomSeed: extraEntropy is set but not a string.')
    }

    return seed.toString();
};

KeyStore.isSeedValid = function (seed) {
    return Mnemonic.isValid(seed, Mnemonic.Words.ENGLISH)
};

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
    const jsonKS = JSON.parse(keystore);

    if (jsonKS.version === undefined || jsonKS.version !== 3) {
        throw new Error('Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.')
    }

    // Create keystore
    const keystoreX = new KeyStore();

    keystoreX.salt = jsonKS.salt;
    keystoreX.hdPathString = jsonKS.hdPathString;
    keystoreX.encSeed = jsonKS.encSeed;
    keystoreX.encHdRootPriv = jsonKS.encHdRootPriv;
    keystoreX.version = jsonKS.version;
    keystoreX.hdIndex = jsonKS.hdIndex;
    keystoreX.encPrivKeys = jsonKS.encPrivKeys;
    keystoreX.addresses = jsonKS.addresses;

    return keystoreX;
};

KeyStore.deriveKeyFromPasswordAndSalt = function (password, salt, callback) {

    // Do not require salt, and default it to 'lightwalletSalt'
    // (for backwards compatibility)
    if (!callback && typeof salt === 'function') {
        callback = salt
        salt = 'lightwalletSalt'
    } else if (!salt && typeof callback === 'function') {
        salt = 'lightwalletSalt'
    }

    const logN = 14;
    const r = 8;
    const dkLen = 32;
    const interruptStep = 200;

    const cb = function (derKey) {
        let err = null;
        let ui8arr = null;
        try {
            ui8arr = (new Uint8Array(derKey));
        } catch (e) {
            err = e
        }
        callback(err, ui8arr);
    };

    scrypt(password, salt, logN, r, dkLen, interruptStep, cb, null);
};

// External API functions

KeyStore.prototype.serialize = function () {
    const jsonKS = {
        'encSeed': this.encSeed,
        'encHdRootPriv': this.encHdRootPriv,
        'addresses': this.addresses,
        'encPrivKeys': this.encPrivKeys,
        'hdPathString': this.hdPathString,
        'salt': this.salt,
        'hdIndex': this.hdIndex,
        'version': this.version
    };

    return JSON.stringify(jsonKS);
};

KeyStore.prototype.getAddresses = function () {

    const prefixedAddresses = this.addresses.map(function (addr) {
        return add0x(addr)
    });

    return prefixedAddresses;

};

KeyStore.prototype.getSeed = function (pwDerivedKey) {

    if (!this.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);
    return paddedSeed.trim();
};

KeyStore.prototype.exportPrivateKey = function (address, pwDerivedKey) {

    if (!this.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    // todo verify and change
    var address = strip0x(address).toLowerCase();
    if (this.encPrivKeys[address] === undefined) {
        throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
    }

    const encPrivKey = this.encPrivKeys[address];
    const privKey = KeyStore._decryptKey(encPrivKey, pwDerivedKey);

    return privKey;
};

KeyStore.prototype.generateNewAddress = function (pwDerivedKey, n) {

    if (!this.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    if (!this.encSeed) {
        throw new Error('KeyStore.generateNewAddress: No seed set');
    }
    n = n || 1;
    const keys = this._generatePrivKeys(pwDerivedKey, n);

    for (let i = 0; i < n; i++) {
        const keyObj = keys[i];
        const address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);
        this.encPrivKeys[address] = keyObj.encPrivKey;
        this.addresses.push(address);
    }

};

KeyStore.prototype.keyFromPassword = function (password, callback) {
    KeyStore.deriveKeyFromPasswordAndSalt(password, this.salt, callback);
};


// Async functions exposed for Hooked Web3-provider
// hasAddress(address, callback)
// signTransaction(txParams, callback)
//
// The function signTransaction() needs the
// function KeyStore.prototype.passwordProvider(callback)
// to be set in order to run properly.
// The function passwordProvider is an async function
// that calls the callback(err, password) with a password
// supplied by the user or by other means.
// The user of the hooked web3-provider is encouraged
// to write their own passwordProvider.
//
// Uses defaultHdPathString for the addresses.

KeyStore.prototype.passwordProvider = function (callback) {

    const password = prompt("Enter password to continue", "Enter password");
    if (!password) {
        return callback(new Error('Password not defined'), null);
    }
    callback(null, password);
}


KeyStore.prototype.hasAddress = function (address, callback) {

    const addrToCheck = strip0x(address);

    if (this.encPrivKeys[addrToCheck] === undefined) {
        callback('Address not found!', false);
    }
    else {
        callback(null, true);
    }

};

KeyStore.prototype.signTransaction = function (txParams, callback) {
    const _this = this;

    const ethjsTxParams = {};

    ethjsTxParams.from = add0x(txParams.from);
    ethjsTxParams.to = add0x(txParams.to);
    ethjsTxParams.gasLimit = add0x(txParams.gas);
    ethjsTxParams.gasPrice = add0x(txParams.gasPrice);
    ethjsTxParams.nonce = add0x(txParams.nonce);
    ethjsTxParams.value = add0x(txParams.value);
    ethjsTxParams.data = add0x(txParams.data);

    const txObj = new Transaction(ethjsTxParams);
    const rawTx = txObj.serialize().toString('hex');
    const signingAddress = strip0x(txParams.from);
    const salt = this.salt;
    const self = this;
    this.passwordProvider(function (err, password, salt) {
        if (err) return callback(err);

        if (!salt) {
            salt = _this.salt
        }

        _this.keyFromPassword(password, function (err, pwDerivedKey) {
            if (err) return callback(err);
            let signedTx;
            try {
                signedTx = signing.signTx(self, pwDerivedKey, rawTx, signingAddress, self.defaultHdPathString);
            } catch (err) {
                return callback(err);
            }
            callback(null, '0x' + signedTx);
        })
    })

};


module.exports = KeyStore;

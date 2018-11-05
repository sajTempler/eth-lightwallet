const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');

function nacl_encodeHex(msgUInt8Arr) {
    const msgBase64 = naclUtil.encodeBase64(msgUInt8Arr);
    return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
    const msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
    return naclUtil.decodeBase64(msgBase64);
}

function addressToPublicEncKey(keystore, pwDerivedKey, address) {
    const privKey = keystore.exportPrivateKey(address, pwDerivedKey);
    const privKeyUInt8Array = nacl_decodeHex(privKey);
    const pubKeyUInt8Array = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey;
    return nacl_encodeHex(pubKeyUInt8Array)
}


function _asymEncryptRaw(keystore, pwDerivedKey, msgUint8Array, myAddress, theirPubKey) {

    if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const privKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
    const privKeyUInt8Array = nacl_decodeHex(privKey);
    const pubKeyUInt8Array = nacl_decodeHex(theirPubKey);
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const encryptedMessage = nacl.box(msgUint8Array, nonce, pubKeyUInt8Array, privKeyUInt8Array);

    return {
        alg: 'curve25519-xsalsa20-poly1305',
        nonce: naclUtil.encodeBase64(nonce),
        ciphertext: naclUtil.encodeBase64(encryptedMessage)
    };
}

function _asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

    if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const privKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
    const privKeyUInt8Array = nacl_decodeHex(privKey);
    const pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

    const nonce = naclUtil.decodeBase64(encMsg.nonce);
    const ciphertext = naclUtil.decodeBase64(encMsg.ciphertext);
    const cleartext = nacl.box.open(ciphertext, nonce, pubKeyUInt8Array, privKeyUInt8Array);

    return cleartext;

}

const asymEncryptString = function (keystore, pwDerivedKey, msg, myAddress, theirPubKey) {

    if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const messageUInt8Array = naclUtil.decodeUTF8(msg);

    return _asymEncryptRaw(keystore, pwDerivedKey, messageUInt8Array, myAddress, theirPubKey);

};

const asymDecryptString = function (keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

    if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const cleartext = _asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress);

    if (cleartext === false) {
        return false;
    }
    else {
        return naclUtil.encodeUTF8(cleartext);
    }

};

const multiEncryptString = function (keystore, pwDerivedKey, msg, myAddress, theirPubKeyArray) {

    if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    const messageUInt8Array = naclUtil.decodeUTF8(msg);
    const symEncryptionKey = nacl.randomBytes(nacl.secretbox.keyLength);
    const symNonce = nacl.randomBytes(nacl.secretbox.nonceLength);

    const symEncMessage = nacl.secretbox(messageUInt8Array, symNonce, symEncryptionKey);

    if (theirPubKeyArray.length < 1) {
        throw new Error('Found no pubkeys to encrypt to.');
    }

    // todo wtf
    let encryptedSymKey = {};
    encryptedSymKey = [];
    for (let i = 0; i < theirPubKeyArray.length; i++) {

        const encSymKey = _asymEncryptRaw(keystore, pwDerivedKey, symEncryptionKey, myAddress, theirPubKeyArray[i]);

        delete encSymKey['alg'];
        encryptedSymKey.push(encSymKey);
    }

    const output = {};
    output.version = 1;
    output.asymAlg = 'curve25519-xsalsa20-poly1305';
    output.symAlg = 'xsalsa20-poly1305';
    output.symNonce = naclUtil.encodeBase64(symNonce);
    output.symEncMessage = naclUtil.encodeBase64(symEncMessage);
    output.encryptedSymKey = encryptedSymKey;

    return output;
};

const multiDecryptString = function (keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

    if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
        throw new Error("Incorrect derived key!");
    }

    let symKey = false;
    for (let i = 0; i < encMsg.encryptedSymKey.length; i++) {
        const result = _asymDecryptRaw(keystore, pwDerivedKey, encMsg.encryptedSymKey[i], theirPubKey, myAddress)
        if (!!result) {
            symKey = result;
            break;
        }
    }

    if (!symKey) {
        return false;
    }
    else {
        const symNonce = naclUtil.decodeBase64(encMsg.symNonce);
        const symEncMessage = naclUtil.decodeBase64(encMsg.symEncMessage);
        const msg = nacl.secretbox.open(symEncMessage, symNonce, symKey);

        if (msg === false) {
            return false;
        }
        else {
            return naclUtil.encodeUTF8(msg);
        }
    }

};

module.exports = {
    asymEncryptString: asymEncryptString,
    asymDecryptString: asymDecryptString,
    multiEncryptString: multiEncryptString,
    multiDecryptString: multiDecryptString,
    addressToPublicEncKey: addressToPublicEncKey
};

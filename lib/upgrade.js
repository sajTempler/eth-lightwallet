const CryptoJS = require('crypto-js');
const keystore = require('./keystore');

const Transaction = require('ethereumjs-tx');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const bitcore = require('bitcore-lib');
const Random = bitcore.crypto.Random;
const Hash = bitcore.crypto.Hash;
const Mnemonic = require('bitcore-mnemonic');
const nacl = require('tweetnacl');
const scrypt = require('scrypt-async');

const legacyDecryptString = function (encryptedStr, password) {
  const decryptedStr = CryptoJS.AES.decrypt(encryptedStr.encStr, password, {'iv': encryptedStr.iv, 'salt': encryptedStr.salt });
  return decryptedStr.toString(CryptoJS.enc.Latin1);
};

const legacyGenerateEncKey = function(password, salt, keyHash) {
  const encKey = CryptoJS.PBKDF2(password, salt, { keySize: 512 / 32, iterations: 150 }).toString();
  const hash = CryptoJS.SHA3(encKey).toString();
  if (keyHash !== hash){
      throw new Error('Invalid Password');
  }
  return encKey;
};

const upgradeOldSerialized = function (oldSerialized, password, callback) {

  // Upgrades old serialized version of the keystore
  // to the latest version
  const oldKS = JSON.parse(oldSerialized);

  if (oldKS.version === undefined || oldKS.version === 1) {

    const derivedKey = legacyGenerateEncKey(password, oldKS.salt, oldKS.keyHash);
    const seed = legacyDecryptString(oldKS.encSeed, derivedKey);

    keystore.createVault({
      password: password,
      seedPhrase: seed,
      salt: 'lightwalletSalt',
      hdPathString: "m/0'/0'/0'"
    }, function (err, newKeyStore) {

      newKeyStore.keyFromPassword(password, function(err, pwDerivedKey){
        const hdIndex = oldKS.hdIndex;
        newKeyStore.generateNewAddress(pwDerivedKey, hdIndex);

        callback(null, newKeyStore.serialize());
      })
    })

  }
  else if (oldKS.version === 2) {
    let salt = 'lightWalletSalt';
    if (oldKS.salt !== undefined) {
      salt = oldKS.salt
    }
    
    keystore.deriveKeyFromPasswordAndSalt(password, salt, function(err, pwKey) {
      const seed = keystore._decryptString(oldKS.encSeed, pwKey).trim();
      const hdPaths = Object.keys(oldKS.ksData);

      let hdPathString = '';
      if (hdPaths.length === 1) {
        hdPathString = hdPaths[0]
      }
      
      keystore.createVault({
        password: password,
        seedPhrase: seed,
        salt: salt,
        hdPathString: hdPathString
      }, function (err, newKeyStore) {

        newKeyStore.keyFromPassword(password, function(err, pwDerivedKey){
          const hdIndex = oldKS.ksData[hdPathString].hdIndex;
          newKeyStore.generateNewAddress(pwDerivedKey, hdIndex);
          callback(null, newKeyStore.serialize());
        })
      })

    })
  }
  else {
    throw new Error('Keystore is not of correct version.')
  }
};


module.exports.upgradeOldSerialized = upgradeOldSerialized;

const expect = require('chai').expect;
const keyStore = require('../lib/keystore');
const upgrade = require('../lib/upgrade');
const encryption = require('../lib/encryption');
const fixtures = require('./fixtures/keystore');

describe("Encryption", function () {

  describe('Asymmetric Encryption', function() {

    it('encrypts and decrypts a string', function (done) {

      const fixture = fixtures.valid[0];
      const pw = Uint8Array.from(fixture.pwDerivedKey);

      keyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: "m/0'/0'/2'"
      }, function (err, ks) {

        ks.generateNewAddress(pw, 2);
        const addresses = ks.getAddresses();
        const pubKey0 = encryption.addressToPublicEncKey(ks, pw, addresses[0]);
        const pubKey1 = encryption.addressToPublicEncKey(ks, pw, addresses[1]);

        const msg = "Hello World!";
        const encrypted = encryption.asymEncryptString(ks, pw, msg, addresses[0], pubKey1);
        const cleartext = encryption.asymDecryptString(ks, pw, encrypted, pubKey0, addresses[1]);
        expect(cleartext).to.equal(msg);
        done()
      })
    });

  });

  describe('Multi-recipient Encryption', function() {

    this.timeout(10000);

    it('encrypts and decrypts a string to multiple parties', function (done) {

      const fixture = fixtures.valid[0];
      const pw = Uint8Array.from(fixture.pwDerivedKey);

      keyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: "m/0'/0'/2'"
      }, function (err, ks) {

        ks.generateNewAddress(pw, 6);
        const addresses = ks.getAddresses();
        const pubKeys = [];
        addresses.map(function(addr) {
          pubKeys.push(encryption.addressToPublicEncKey(ks, pw, addr))
        });

        const msg = "Hello World to multiple people!";
        const encrypted = encryption.multiEncryptString(ks, pw, msg, addresses[0], pubKeys.slice(0,4));
        let cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[0]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[1]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[2]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[3]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[4]);
        expect(cleartext).to.equal(false);
        done();
      });

    });
  });
});

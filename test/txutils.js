const expect = require('chai').expect;
const txutils = require('../lib/txutils');
const fixtures = require('./fixtures/txutils');

describe("Utils", function() {

  describe("_getTypesFromAbi", function() {
    fixtures.valid.forEach(function (f) {
      it('returns valid types of function ' + '"' + f.func + '"', function () {

        const types = txutils._getTypesFromAbi(f.abi, f.func);

        expect(types).to.deep.equal(f.types)
      })
    })
  });

  describe("functionTx", function() {
    fixtures.valid.forEach(function (f) {
      it('correct transaction generated', function () {

        const tx = txutils.functionTx(f.abi, f.func, f.args, f.txObject);

        expect(tx).to.equal(f.funcTx)
      })
    })
  });

  describe("createdContractAddress", function() {
    fixtures.valid.forEach(function (f) {
      it('correct contract address is generated', function () {

        const address = txutils.createdContractAddress(f.fromAddress, f.txObject.nonce);

        expect(address).to.equal(f.contractAddress)
      })
    })
  });

  describe("createContractTx valueTx", function() {
    fixtures.valid.forEach(function (f) {
      it('createContractTx returns the same as valueTx and contractAddress', function () {

        const contractTxData = txutils.createContractTx(f.fromAddress, f.txObject);
        const txData = txutils.valueTx(f.txObject);
        const address = txutils.createdContractAddress(f.fromAddress, f.txObject.nonce);
        expect(address).to.equal(contractTxData.addr);
        expect(txData).to.equal(contractTxData.tx)
      })
    })
  });

});

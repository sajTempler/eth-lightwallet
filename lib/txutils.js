const Transaction = require('ethereumjs-tx');
const coder = require('web3-eth-abi');
const rlp = require('rlp');
const CryptoJS = require('crypto-js');

function add0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  if (input.length < 2 || input.slice(0,2) !== '0x') {
    return '0x' + input;
  }

  return input;
}

function strip0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length >= 2 && input.slice(0,2) === '0x') {
    return input.slice(2);
  }
  else {
    return input;
  }
}

function _encodeFunctionTxData (functionName, types, args) {

  const fullName = functionName + '(' + types.join() + ')';
  const signature = CryptoJS.SHA3(fullName, { outputLength: 256 }).toString(CryptoJS.enc.Hex).slice(0, 8);
  // const dataHex = '0x' + signature + coder.encodeParams(types, args);
  // When updating to web3 1.0.0, replace by
  const dataHex = coder.encodeFunctionSignature(fullName) + coder.encodeParameters(types, args).replace('0x','');

  return dataHex;
}

function _getTypesFromAbi (abi, functionName) {

  function matchesFunctionName(json) {
    return (json.name === functionName && json.type === 'function');
  }

  function getTypes(json) {
    return json.type;
  }

  const funcJson = abi.filter(matchesFunctionName)[0];

  return (funcJson.inputs).map(getTypes);
}

function functionTx (abi, functionName, args, txObject) {
  // txObject contains gasPrice, gasLimit, nonce, to, value

  const types = _getTypesFromAbi(abi, functionName);
  const txData = _encodeFunctionTxData(functionName, types, args);

  const txObjectCopy = {};
  txObjectCopy.to = add0x(txObject.to);
  txObjectCopy.gasPrice = add0x(txObject.gasPrice);
  txObjectCopy.gasLimit = add0x(txObject.gasLimit);
  txObjectCopy.nonce = add0x(txObject.nonce);
  txObjectCopy.data = add0x(txData);
  txObjectCopy.value = add0x(txObject.value);

  return '0x' + (new Transaction(txObjectCopy)).serialize().toString('hex');
}

function createdContractAddress (fromAddress, nonce) {
  const rlpEncodedHex = rlp.encode([new Buffer(strip0x(fromAddress), 'hex'), nonce]).toString('hex');
  const rlpEncodedWordArray = CryptoJS.enc.Hex.parse(rlpEncodedHex);
  const hash = CryptoJS.SHA3(rlpEncodedWordArray, {outputLength: 256}).toString(CryptoJS.enc.Hex);

  return '0x' + hash.slice(24);
}

function createContractTx (fromAddress, txObject) {
  // txObject contains gasPrice, gasLimit, value, data, nonce

  const txObjectCopy = {};
  txObjectCopy.to = add0x(txObject.to);
  txObjectCopy.gasPrice = add0x(txObject.gasPrice);
  txObjectCopy.gasLimit = add0x(txObject.gasLimit);
  txObjectCopy.nonce = add0x(txObject.nonce);
  txObjectCopy.data = add0x(txObject.data);
  txObjectCopy.value = add0x(txObject.value);

  const contractAddress = createdContractAddress(fromAddress, txObject.nonce);
  const tx = new Transaction(txObjectCopy);

  return {tx: '0x' + tx.serialize().toString('hex'), addr: contractAddress};
}

function valueTx (txObject) {
  // txObject contains gasPrice, gasLimit, value, nonce

  const txObjectCopy = {};
  txObjectCopy.to = add0x(txObject.to);
  txObjectCopy.gasPrice = add0x(txObject.gasPrice);
  txObjectCopy.gasLimit = add0x(txObject.gasLimit);
  txObjectCopy.nonce = add0x(txObject.nonce);
  txObjectCopy.value = add0x(txObject.value);

  const tx = new Transaction(txObjectCopy);

  return '0x' + tx.serialize().toString('hex');
}

module.exports = {
  _encodeFunctionTxData: _encodeFunctionTxData,
  _getTypesFromAbi: _getTypesFromAbi,
  functionTx: functionTx,
  createdContractAddress: createdContractAddress,
  createContractTx: createContractTx,
  valueTx: valueTx
};

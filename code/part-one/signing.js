'use strict';

const secp256k1 = require('secp256k1');
const { randomBytes, createHash } = require('crypto');


/**
 * A function which generates a new random Secp256k1 private key, returning
 * it as a 64 character hexadecimal string.
 *
 * Example:
 *   const privateKey = createPrivateKey();
 *   console.log(privateKey);
 *   // 'e291df3eede7f0c520fddbe5e9e53434ff7ef3c0894ed9d9cbcb6596f1cfe87e'
 */
const createPrivateKey = () => {
  // Enter your solution here
  let privKey;
  do {
    privKey = randomBytes(32);
  } while (!secp256k1.privateKeyVerify(privKey));
  return privKey.toString('hex');
};

/**
 * A function which takes a hexadecimal private key and returns its public pair
 * as a 66 character hexadecimal string.
 *
 * Example:
 *   const publicKey = getPublicKey(privateKey);
 *   console.log(publicKey);
 *   // '0202694593ddc71061e622222ed400f5373cfa7ea607ce106cca3f039b0f9a0123'
 *
 * Hint:
 *   Remember that the secp256k1-node library expects raw bytes (i.e Buffers),
 *   not hex strings! You'll have to convert the private key.
 */
const getPublicKey = privateKey => {
  // Your code here
  return secp256k1.publicKeyCreate(Buffer.from(privateKey, 'hex')).toString('hex');

};

/**
 * A function which takes a hex private key and a string message, returning
 * a 128 character hexadecimal signature.
 *
 * Example:
 *   const signature = sign(privateKey, 'Hello World!');
 *   console.log(signature);
 *   // '4ae1f0b20382ad628804a5a66e09cc6bdf2c83fa64f8017e98d84cc75a1a71b52...'
 *
 * Hint:
 *   Remember that you need to sign a SHA-256 hash of the message,
 *   not the message itself!
 */
const sign = (privateKey, message) => {
  // Your code here

  const hash = createHash('sha256');

  hash.update(message); 
  var f = Buffer.from(hash.copy().digest('hex'), 'hex');
  //console.log(Buffer.from(message, 'hex'));
  //console.log(message, privateKey);
 
  var g = secp256k1.sign(f, Buffer.from(privateKey, 'hex'));

  return (g.signature.toString('hex'));
};

/**
 * A function which takes a hex public key, a string message, and a hex
 * signature, and returns either true or false.
 *
 * Example:
 *   console.log( verify(publicKey, 'Hello World!', signature) );
 *   // true
 *   console.log( verify(publicKey, 'Hello World?', signature) );
 *   // false
 */
const verify = (publicKey, message, signature) => {
  // Your code here

};

module.exports = {
  createPrivateKey,
  getPublicKey,
  sign,
  verify
};
/*
let privKey;
do {
  privKey = randomBytes(32);
} while (!secp256k1.privateKeyVerify(privKey));

console.log(privKey);

console.log(randomBytes(32));//
console.log(secp256k1.publicKeyCreate(Buffer.from('a65bce8d77b9ec6b92b6b63e2700bd28ae49be76bc45299d980248d0ef2fbead', 'hex')));


//console.log(secp256k1.sign());
//var g = secp256k1.sign(Buffer.from(msg, 'hex'), Buffer.from(pk, 'hex'));
const hash = createHash('sha256');

hash.update('nQebnMyFKqRxighivlYJDwlJDE0GQGPvJtkoL859rmkdcgzTKTB3pcP2giCdX9GKRynT0dkfg1txxHkVSzBolgQtaWCd4oT1iQ1t0g8KrHp99mfrCbhRetuqDiryDt7VhgXWdRrrAYAxqwWbSLSK95GnHLQ1EfGEqEikYwjhAubtVg');
console.log(hash.copy().digest('utf8'));

//console.log(createHash(msg));

var pk = '95eee4553802be3486d2106e87caf0bee798381ce2570a9ac2222d609ab0c2af';
var msg = 'nQebnMyFKqRxighivlYJDwlJDE0GQGPvJtkoL859rmkdcgzTKTB3pcP2giCdX9GKRynT0dkfg1txxHkVSzBolgQtaWCd4oT1iQ1t0g8KrHp99mfrCbhRetuqDiryDt7VhgXWdRrrAYAxqwWbSLSK95GnHLQ1EfGEqEikYwjhAubtVg';
console.log(sign(pk, msg));
*/
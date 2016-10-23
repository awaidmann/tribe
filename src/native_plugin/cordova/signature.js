var exec = require('cordova/exec');

/**
  @typedef {Function} CordovaCallback
  @param {Error=} err - Possible error. Null if-and-only-if 'result' is defined.
  @param {Any=} result - Possible successful results. Null if-and-only-if 'err' is defined.
*/

/**
  @class plugin.SignaturePlugin
  @memberof plugin
*/
function SignaturePlugin() {
 console.log("init signature.js");
}

/**
  <p>Signs an arbitrary object using ECDSA with a SHA1 prehash and returns signature (and signing metadata) as property on original object.</p>
  <p>Both the returned Promise and the callback are called when the function completes. Using both is not recommended as you may be duplicating efforts.</p>
  @function sign
  @param {Object} data - Arbitrary data to sign.
  @param {String} signingKeyID - Firebase id of current public half of device's public/private key pair.
  @param {String} signerID - Logged in user's Firebase uid.
  @param {Number} lastModified - Should be set to current time, but can be set to any arbitrary timestamp.
  @param {CordovaCallback=} cb - Optional callback that will be run after function completes. 'result' will be a {@link SignedData|signed object}.
  @return {Promise} New Promise which resolves with a {@link SignedData|signed object}, rejects if device keys have not been configured correctly or if any param is undefined/null.
  @static
  @memberof plugin.SignaturePlugin
*/
SignaturePlugin.prototype.sign = function(data, signingKeyID, signerID, lastModified, cb) {
  return this.exec("sign", [data, signingKeyID, signerID, lastModified], cb);
}

/**
  <p>Verify that the ECDSA + SHA1 signature on 'dataWithSig' matches the computed signature on the remainder of the properties (including the signature metadata, signerID, signingKeyID, lastModified).</p>
  <p>Both the returned Promise and the callback are called when the function completes. Using both is not recommended as you may be duplicating efforts.</p>
  @function verify
  @param {SignedData} dataWithSig - Previously signed data object. Must contain signature and all signature metadata.
  @param {String} signerPubKeyStr - PEM endcoded EC public key string.
  @param {String} signerID - Uid of author of most recent changes to 'dataWithSig'. Also, should be owner of 'signerPubKeyStr'.
  @param {CordovaCallback=} - Optional callback that will be run after function completes. 'result' will have value of 'OK' if signature can be verified.
  @return {Promise} New Promise which resolves if signature can be verified, rejects if device keys have not been configured correctly, if any param is undefined/null, or if signature cannot be verified.
  @static
  @memberof plugin.SignaturePlugin
*/
SignaturePlugin.prototype.verify = function(dataWithSig, signerPubKeyStr, signerID, cb) {
  return this.exec("verify", [dataWithSig, signerPubKeyStr, signerID], cb);
}

/**
  <p>Generates an Elliptic Curve public/private key pair if one does not already exist on the device or if the one that does exist is expired.</p>
  <p>Both the returned Promise and the callback are called when the function completes. Using both is not recommended as you may be duplicating efforts.</p>
  @function genKeyPairIfNecessary
  @param {String} userID - Uid of current user.
  @param {CordovaCallback=} cb - Optional callback that will be run after function completes. 'result' will be a boolean indicating whether key creation was necessary.
  @return {Promise} New Promise which resolves with boolean indicating whether key creation was necessary. Rejects if key could not be added to the device keychain.
  @static
  @memberof plugin.SignaturePlugin
*/
SignaturePlugin.prototype.genKeyPairIfNecessary = function(userID, cb) {
  return this.exec("genKeyPairIfNecessary", [userID], cb);
}

/**
  <p>Fetches the EC PEM encoded public key string from the device keychain.</p>
  <p>Both the returned Promise and the callback are called when the function completes. Using both is not recommended as you may be duplicating efforts.</p>
  @function publicKey
  @param {String} userID - Uid of current user.
  @param {CordovaCallback=} cb - Optional callback that will be run after function completes. 'result' will be the PEM encoded public key.
  @return {Promise} New Promise which resolves with PEM encoded public key. Rejects if key could not be found.
  @memberof plugin.SignaturePlugin
*/
SignaturePlugin.prototype.publicKey = function(userID, cb) {
  return this.exec("getPublicKey", [userID], cb);
}

SignaturePlugin.prototype.exec = function(funcName, payload, cb) {
  return new Promise( function(resolve, reject) {
    exec(
      function(result) {
       if (cb) {
         cb(null, result);
       }
       resolve(result);
      },
      function(err) {
       if (cb) {
         cb(err);
       }
       reject(err);
     },"SignaturePlugin", funcName, payload);
  })
}

 var sigServ = new SignaturePlugin();
 module.exports = sigServ;

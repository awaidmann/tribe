class Key {
  constructor(orgID, ownerID, keyID, keyPEM, expiration, signatures, trust) {
    this.orgID = orgID
    this.ownerID = ownerID
    this.keyID = keyID
    this.key = keyPEM
    this.expiration = expiration
    this.signatures = processSignatures(orgID, signatures)
    this.trust = processTrust(ownerID, keyID, trust)

    if (!this.orgID) { throw 'Invalid organization' }
    if (!this.ownerID) { throw 'Invalid owner' }
    if (!this.key || !this.keyID) { throw 'Invalid key material' }
  }

  formatForVerify() {
    return this.formatForVerifyLink(this)
  }

  formatForVerifyLink(parentKey) {
    if (parentKey) {
      const parentSig = this.signatures[parentKey.keyID] ? this.signatures[parentKey.keyID] : {}
      return {
        keyID: this.keyID,
        publicKey: this.key,
        expiration: this.expiration,
        ownerID: this.ownerID,
        signingKeyID: parentKey.keyID,
        signerID: parentKey.ownerID,
        lastModified: parentSig.timestamp,
        sig: parentSig.signature
      }
    }
    return {}
  }

  formatForSign(signingKey) {
    return {
      keyID: this.keyID,
      publicKey: this.key,
      ownerID: this.ownerID,
      expiration: this.expiration,
    }
  }

  static formatSignedKey(signedKey) {
    let formatted = {}
    formatted[`${signedKey.keyID}/signatures/${signedKey.signingKeyID}`] = {
      signerID: signedKey.signerID,
      timestamp: signedKey.lastModified,
      sig: signedKey.sig
    }
    return formatted
  }

  formatTrustForSign(trustChain) {
    const links = Array.isArray(trustChain) ? trustChain : [trustChain]
    return Object.assign({},
      this.trust.trustEntities,
      links.reduce((acc, link, index, srcArr) => {
        acc[link.keyID] = {
          trustedUserID: link.ownerID,
          trustLevel: index + 1,
          chain: [this.keyID].concat(srcArr.slice(0, index)
            .map(key => key.keyID))
            .reduce((objAcc, keyID, i) => {
              objAcc[i] = keyID
              return objAcc
            }, {})
        }
        return acc
      }, {}))
  }

  static formatSignedTrust(signedTrust) {
    const trust = Object.assign({}, signedTrust)
    delete trust.signerID
    return trust
  }

  isEqual(otherKey) {
    if (otherKey && otherKey.signatures && this.signatures) {
      const mySig = this.signatures[this.keyID]
      const otherSig = otherKey.signatures[otherKey.keyID]

      return mySig && otherSig && mySig.signature === otherSig.signature
        && this.trust && otherKey.trust && this.trust.signature === otherKey.trust.signature
    }
    return false
  }

  isActive() {
    return this.expiration && this.expiration >= Date.now()
  }

  refresh() {
    return Key.loadInfo(this.orgID, this.keyID)
  }

  static hydrate(keyBean) {
    return new Key(keyBean.orgID, keyBean.ownerID, keyBean.keyID, keyBean.key, keyBean.expiration, keyBean.signatures, keyBean.trust)
  }

  static loadInfo(orgID, keyID) {
    return new Promise( (resolve, reject) => {
      firebase.database().ref(`/orgs/${orgID}/keys/${keyID}`)
        .once('value')
        .then(
          snapshot => {
            const keyInfo = snapshot.val()
            const warnKey = new Key(orgID, keyInfo.ownerID, keyID, keyInfo.publicKey, keyInfo.expiration, keyInfo.signatures, keyInfo.trust)
            resolve(warnKey)
          },
          err => reject(err)
        )
    })
  }
}

function processSignatures(orgID, signatures) {
  let sigAcc = {}
  for(let signingKeyID in signatures) {
    const sigData = signatures[signingKeyID]
    sigAcc[signingKeyID] = new KeySignature(sigData.sig, orgID, sigData.signerID, signingKeyID, sigData.timestamp)
  }
  return sigAcc
}

function processTrust(ownerID, keyID, trust) {
  const trustInfo = trust ? trust : {}
  const trustSig = trustInfo.sig
  const trustTime = trustInfo.lastModified
  delete trustInfo.sig
  delete trustInfo.lastModified

  return new KeyTrust(trustInfo, ownerID, keyID, trustSig, trustTime)
}

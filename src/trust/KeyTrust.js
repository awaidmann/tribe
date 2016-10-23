class KeyTrust {
  constructor(trustEntities, signerID, signingKeyID, signature, lastModified) {
    this.trustEntities = trustEntities
    this.signerID = signerID
    this.signingKeyID = signingKeyID
    this.signature = signature
    this.lastModified = lastModified
  }

  formatForVerify() {
    const sanitized = Object.keys(this.trustEntities).reduce( (trustAcc, trustID) => {
      const trust = Object.assign({}, this.trustEntities[trustID])
      if (trust.chain) {
        trust.chain = trust.chain.reduce( (acc, keyID, i) => {
          acc[`${i}`] = keyID
          return acc
        }, {})
      }
      trustAcc[trustID] = trust
      return trustAcc
    }, {})

    return Object.assign({}, sanitized, {
      signerID: this.signerID,
      signingKeyID: this.signingKeyID,
      sig: this.signature,
      lastModified: this.lastModified
    })
  }

  trustedKeyIDs() {
    return Object.keys(this.trustEntities)
      .sort((idA, idB) => this.trustEntities[idA].trustLevel - this.trustEntities[idB].trustLevel)
  }

  parentLinkID(trusteeID) {
    const trust = this.trustEntities[trusteeID]
    if (trust) {
      return (trust.chain || {})[`${trust.trustLevel - 1}`]
    }
  }
}

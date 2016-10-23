class KeySignature {
  constructor(signature, orgID, signerID, keyID, timestamp) {
    this.signature = signature
    this.orgID = orgID
    this.signerID = signerID
    this.keyID = keyID
    this.timestamp = timestamp

    if (!this.signature) { throw 'Invalid signature' }
    if (!this.orgID) { throw 'Invalid organization' }
    if (!this.signerID) { throw 'Invalid signer' }
    if (!this.keyID) { throw 'Invalid key material' }
    if (!this.timestamp) { throw 'Invalid timestamp' }
  }
}

'use strict'

const M = require('../macros')
const Rule = require('../Rule.js')
const Clause = require('../Clause.js')

const signerID  = M.sibilingVal(0, 'signerID')
const isOrgUser = Clause.this(M.isOrgUser)

const newHasChildren = function() {
  return Clause.this("newData" + M.hasChildren.apply(M, arguments))
}

// keys/summary/$uid/$keyID
const pubKeysMatch  = M.newSibilingEquals(3, "$keyID+'/publicKey'", M.val())
const ownersMatch   = M.newSibilingEquals(3, "$keyID+'/ownerID'", "$uid")

// keys/$keyID
const signedOwnKey    = Clause.this("newData.child('signatures')" + M.hasChildren("$keyID"))
const trustsOwnKey    = Clause.this("newData.child('trust')" + M.hasChildren("$keyID"))
const isPEMKey        = Clause.this("newData.val().matches(/^-----BEGIN PUBLIC KEY-----\\s[0-9a-zA-Z+\\/\\s]*(=|==)?\\s-----END PUBLIC KEY-----$/)")
const gtYesterday     = Clause.this(M.val() + " >= (now - 86400000)")
const ltAYearFromNow  = Clause.this(M.val() + " <= (now + 31536000000)")
const ownerIsEditing  = function(depth) {
  return M.newSibilingEquals(depth, "'ownerID'", 'auth.uid')
}

// keys/$keyID/signatures
const signedByOwner         = Clause.this(signerID + " == " + M.sibilingVal(2, 'ownerID'))
const signingKeyIsSignedKey = Clause.this("$signingKeyID == $keyID")
const signerOwnsSigningKey  = Clause.this("root.child('orgs/'+$orgID+'/keys/'+$signingKeyID+'/ownerID').val() == "+ signerID)

// keys/$keyID/signatures
const trustedKeyIsCurrentKey    = Clause.this("$keyID == $trustedKeyID")
const trustedUserOwnsTrustedKey = Clause.this("root.child('/orgs/'+$orgID+'/keys/'+$trustedKeyID+'/ownerID').val() == newData.child('trustedUserID').val()")

// keys/$keyID/trust
const gtZero    = Clause.this(M.val() + " >= 0")
const keyExists = Clause.this("root.hasChild('/orgs/'+$orgID+'/keys/'+newData.val())")

exports.rules = new Rule("keys")
  .read(isOrgUser)
  .write(isOrgUser)

  .child( new Rule('summary', '$uid', "$keyID")
    .validate( pubKeysMatch.and(ownersMatch) ))

  .child( new Rule('$keyID')
    .indexOn('ownerID')
    .validate( newHasChildren('publicKey', 'ownerID', 'expiration', 'signatures', 'trust')
      .and(signedOwnKey)
      .and(trustsOwnKey))

    .child( new Rule('publicKey').validate( M.wasNull().and(ownerIsEditing(1)).and(isPEMKey) ))

    .child( new Rule('ownerID').validate( M.wasNull().and(M.isCurrentUser()) ))

    .child( new Rule('expiration')
      .validate( M.wasNull()
        .and(ownerIsEditing(1))
        .and(M.isValidTimestamp())
        // .and(gtYesterday)
        // .and(ltAYearFromNow)
      ))

    .child( new Rule('signatures', '$signingKeyID')
      .validate( newHasChildren('signerID', 'timestamp', 'sig')
        .and( Clause.ifThenElse(signedByOwner, signingKeyIsSignedKey, signerOwnsSigningKey) ))

      .child( new Rule('signerID').validate( M.isCurrentUser() ))

      .child( new Rule('timestamp').validate( M.isValidTimestamp() ))

      .child( new Rule('sig').validate( M.isBase64Signature() ))
      .strict())

    .child( new Rule('trust')
      .child( new Rule('$trustedKeyID')
        .validate( newHasChildren('trustedUserID', 'trustLevel')
          .and( Clause.this(ownerIsEditing(2).and(trustedKeyIsCurrentKey))
            .or(trustedUserOwnsTrustedKey)))

        .child( new Rule('trustedUserID').validate( M.isString() ))

        .child( new Rule('trustLevel').validate( M.isNumber().and(gtZero) ))

        .child( new Rule('chain', '$linkIndex').validate( keyExists ) )
        .strict())
      .child( new Rule('lastModified').validate( M.isValidTimestamp() ))
      .child( new Rule('sig').validate( M.isBase64Signature() ))
    ).strict())

  .build()

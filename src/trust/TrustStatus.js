const ts_Success = 0
const ts_Connect = 1
const ts_ValidateLink = 2
const ts_Compare = 3
const ts_Validate = 4
const ts_Fetch = 5

const ts_ValidateFail = -1
const ts_RetryFail = -2

class TrustStatus {
  constructor(keyOrKeyID, linkFromStatus) {
    this.priority = ts_Fetch
    this.key = keyOrKeyID || {}
    this.mutual = {}
    this.retries = 3
    this.cachedPaths = {}

    if (linkFromStatus) {
      this.mutual[linkFromStatus.keyID()] = {
        link: linkFromStatus,
        valid: false
      }
    }
  }

  static get SUCCESS() { return ts_Success }
  static get FETCH() { return ts_Fetch }
  static get VALIDATE() { return ts_Validate }
  static get VALIDATE_LINK() { return ts_ValidateLink }
  static get COMPARE() { return ts_Compare }
  static get CONNECT() { return ts_Connect }

  static get VALIDATE_FAIL() { return ts_ValidateFail }
  static get RETRY_FAIL() { return ts_RetryFail }

  connects(startStatus, endStatus) {
    return new Promise( (resolve, reject) => {
      const toStart = this.linksTo(startStatus, new Set())
      const toEnd = this.linksTo(endStatus, new Set())
      if (toStart.length && toEnd.length && this.keyID() === toStart[toStart.length - 1] && this.keyID() === toEnd[toEnd.length - 1]) {
        toEnd.pop()
        this.cachedPaths[startStatus.keyID()] = toStart.concat(toEnd.reverse())
        this.cachedPaths[endStatus.keyID()] = Array.from(this.cachedPaths[startStatus.keyID()]).reverse()
        return resolve(this)
      } else if (toStart.length && startStatus.keyID() === toStart[0] && endStatus.keyID() === toStart[toStart.length - 1]) {
        this.cachedPaths[startStatus.keyID()] = toStart
        this.cachedPaths[endStatus.keyID()] = Array.from(toStart).reverse()
        return resolve(this)
      } else if (toEnd.length && endStatus.keyID() === toEnd[0] && startStatus.keyID() === toEnd[toEnd.length - 1]) {
        this.cachedPaths[startStatus.keyID()] = Array.from(toEnd).reverse()
        this.cachedPaths[endStatus.keyID()] = toEnd
        return resolve(this)
      } else {
        return reject(new Error('Could not resolve trust'))
      }
    })
  }

  linksTo(targetStatus, visited) {
    const targetID = targetStatus.keyID()
    if (this === targetStatus) {
      this.cachedPaths[targetID] = [targetID]
    } else if (!visited.has(this.keyID()) && !this.cachedPaths[targetID]) {
      const allKeys = Object.keys(this.mutual)

      const allPaths = allKeys.reduce(
        (pathAcc, keyID) => {
          if (keyID !== this.keyID()) {
            const link = this.mutual[keyID]
            let subPath
            if (link && link.valid) {
              subPath = link.link.linksTo(targetStatus, new Set([this.keyID(), ...visited]))
            }
            if (subPath && subPath.length) {
              pathAcc.push(subPath)
            }
          }
          return pathAcc
      }, [])

      const firstPath = allPaths.find( path => path.length && path[0] === targetStatus.keyID() )
      this.cachedPaths[targetID] = []
      if (firstPath) {
        firstPath.push(this.keyID())
        this.cachedPaths[targetID] = firstPath
      }
    }
    return this.cachedPaths[targetID]
  }

  notifyValidStatus(isValid, otherStatus) {
    const otherKeyID = otherStatus.keyID()
    this.mutual[otherKeyID].valid = isValid
    otherStatus.mutual[this.keyID()].valid = isValid
  }

  linksToValidate() {
    return Object.keys(this.mutual)
      .reduce( (mutualAcc, mutualID) => {
        const mutStatus = this.mutual[mutualID]
        if (mutStatus && !mutStatus.valid && mutStatus.link.key instanceof Key && this.key.signatures[mutualID]) {
          mutualAcc.push(mutStatus.link || {})
        }
        return mutualAcc
      }, [])
  }

  keyID() {
    return this.key instanceof Key ? this.key.keyID : this.key
  }

  setMutualValidate(validAgainst) {
    if (validAgainst && validAgainst instanceof TrustStatus) {
      if (!this.mutual[validAgainst.keyID()]) {
        this.mutual[validAgainst.keyID()] = {
          link: validAgainst,
          valid: false
        }
      }
      if (!validAgainst.mutual[this.keyID()]) {
        validAgainst.mutual[this.keyID()] = {
          link: this,
          valid: false
        }
      }
    }
  }

  toRetry(canCB, cannotCB) {
    if (this.priority == ts_Fetch) {
      this.priority = ts_Fetch
      if (this.retries > 0) {
        this.retries = this.retries - 1
        canCB(this)
      } else {
        this.toRetryFail()
        cannotCB(this)
      }
    }
    return this
  }

  toConnect() {
    if (this.priority == ts_ValidateLink) {
      this.priority = ts_Connect
    }
    return this
  }

  toValidate(key) {
    if (this.priority == ts_Fetch) {
      this.priority = ts_Validate
      if (key) {
        this.key = key
      }
    }
    return this
  }

  toCompare() {
    if (this.priority == ts_Validate) {
      this.priority = ts_Compare
    }
    return this
  }

  toValidateLink(validAgainst) {
    if (this.priority == ts_Compare) {
      this.priority = ts_ValidateLink
    }
    this.setMutualValidate(validAgainst)
    return this
  }

  toSuccess() {
    if (this.priority == ts_Connect) {
      this.priority = ts_Success
    }
    return this
  }

  toValidateFail() {
    if (this.priority == ts_Validate) {
      this.priority = ts_ValidateFail
    }
    return this
  }

  toRetryFail() {
    if (this.priority == ts_Fetch) {
      this.priority = ts_RetryFail
    }
    return this
  }
}

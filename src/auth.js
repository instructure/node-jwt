const util = require("util")
const jwt = require("jsonwebtoken")
const consul = require("./consul")

exports.UnauthorizedError = function UnauthorizedError(...args) {
  let error, message
  if (args.length > 1) {
    ;[error, message] = args
  } else {
    ;[message] = args
  }

  this.name = this.constructor.name
  this.message = message
  if (error && error.message) {
    this.JWTError = error.message
  }
  Error.call(this)
  Error.captureStackTrace(this, this.constructor)
}
util.inherits(exports.UnauthorizedError, Error)

//
// private methods
//

exports._maxAge = function _maxAge() {
  return process.env.MAX_JWT_AGE || "5s"
}

exports._deny = function _deny(response, errors) {
  response.status(401)
  response.json({ errors })
}

exports._buildKeystore = async function _buildKeystore() {
  let consulKeystore = [],
    envKeystore = []
  if (process.env.CONSUL_JWT_SECRET_PREFIX) {
    consulKeystore = await consul.getSigningSecrets()
  }
  if (process.env.AUTH_SECRET) {
    const keys = process.env.AUTH_SECRET.split(/\s+/)
    envKeystore = keys.map(key => {
      const parts = key.split(":")
      if (parts.length === 1) {
        const [value] = parts
        return { default: Buffer.from(value, "base64") }
      } else if (parts.length === 2) {
        const [kid, value] = parts
        return { [kid]: Buffer.from(value, "base64") }
      } else {
        return undefined
      }
    })
  }
  if (consulKeystore || envKeystore) {
    // flattens from [{a:1}, undefined, {b:2}] to {a:1, b:2}
    return Object.assign({}, ...consulKeystore, ...envKeystore)
  }
  throw new exports.UnauthorizedError("auth secrets unavailable")
}

exports._getToken = function _getToken(req) {
  if (req.query && req.query.token) {
    return req.query.token
  } else if (req.headers && req.headers.authorization) {
    const parts = req.headers.authorization.split(" ")
    if (parts.length === 2) {
      const [scheme, credentials] = parts
      if (scheme === "Bearer") {
        return credentials
      }
    }
    throw new exports.UnauthorizedError(
      "Format is Authorization: Bearer [token]"
    )
  }
  throw new exports.UnauthorizedError("No authorization token was found")
}

exports._verifyToken = async function _verifyToken(token) {
  const keystore = await exports._buildKeystore()
  const options = {
    maxAge: exports._maxAge(),
    algorithms: ["HS256"],
  }
  const verifiers = [
    function verifyWithKid() {
      try {
        const decoded = jwt.decode(token, { complete: true })
        if (decoded && decoded.header && decoded.header.kid) {
          const kid = decoded.header.kid
          const key = keystore[kid]
          if (key) {
            return [undefined, jwt.verify(token, key, options)]
          }
        }
        return ["kid verification failed", undefined]
      } catch (err) {
        return [err, undefined]
      }
    },
    function verifyWithDefault() {
      try {
        if (keystore.default) {
          return [undefined, jwt.verify(token, keystore.default, options)]
        }
        return ["default verification failed", undefined]
      } catch (err) {
        return [err, undefined]
      }
    },
    function verifyWithKeystore() {
      for (const kid in keystore) {
        if (keystore.hasOwnProperty(kid) && kid !== "default") {
          try {
            return [undefined, jwt.verify(token, keystore[kid], options)]
          } catch (err) {
            // ignore key that doesn't work and move on to the next one
          }
        }
      }
      return ["all verification failed", undefined]
    },
  ]

  let error, payload
  for (const verifier of verifiers) {
    ;[error, payload] = verifier()
    // Error "invalid signature" means key didn't match - continue checking
    if (error && error.message && error.message !== "invalid signature") {
      throw new exports.UnauthorizedError(error, "Verification Error")
    }
    if (payload) break
  }

  if (!payload) {
    throw new exports.UnauthorizedError("Verification Error: No matching keys")
  }
  return payload
}

//
// public methods
//

exports.required = function required() {
  return (
    process.env.NODE_ENV === "production" || process.env.REQUIRE_AUTH === "true"
  )
}

exports.middleware = async function middleware(req, res, next) {
  try {
    const token = exports._getToken(req)
    res.locals.payload = await exports._verifyToken(token)
    next()
  } catch (err) {
    next(err)
  }
}

exports.errorHandler = function errorHandler(err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    exports._deny(res, err)
  } else {
    next(err)
  }
}

exports.createToken = async function createToken(payload, kid) {
  try {
    const keystore = await exports._buildKeystore()
    const key =
      keystore[kid] || keystore.default || keystore[Object.keys(keystore)[0]]
    const signingKid = Object.keys(keystore).find(k => keystore[k] === key)
    return jwt.sign(payload, key, { header: { kid: signingKid } })
  } catch (err) {
    throw new exports.UnauthorizedError(err, "Token signing failed")
  }
}

exports.bootstrapConsul = async function bootstrapConsul() {
  await consul.bootstrap()
}

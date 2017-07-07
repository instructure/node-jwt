const util = require("util")
const jwt = require("jsonwebtoken")

exports._maxAge = function _maxAge() {
  return process.env.MAX_JWT_AGE || "5s"
}

exports._deny = function _deny(response, errors) {
  response.status(401)
  response.json({ errors })
}

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

exports._buildKeystore = function _buildKeystore() {
  if (process.env.AUTH_SECRET) {
    const keys = process.env.AUTH_SECRET.split(/\s+/)
    if (keys) {
      const keystore = keys.map(key => {
        const parts = key.split(":")
        if (parts.length === 1) {
          const [value] = parts
          return { default: value }
        } else if (parts.length === 2) {
          const [kid, value] = parts
          return { [kid]: value }
        } else {
          return undefined
        }
      })
      // flattens from [{a:1}, {b:2}] to {a:1, b:2}
      return Object.assign({}, ...keystore)
    }
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

exports._createToken = function _createToken(payload, kid) {
  try {
    const keystore = exports._buildKeystore()
    const key =
      keystore[kid] || keystore.default || keystore[Object.keys(keystore)[0]]
    return jwt.sign(payload, key, { header: { kid } })
  } catch (err) {
    throw new exports.UnauthorizedError(err, "Token signing failed")
  }
}

exports._verifyToken = function _verifyToken(token) {
  const keystore = exports._buildKeystore()
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
          } catch (err) {} //eslint-disable-line no-empty
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

exports.required = function required() {
  return (
    process.env.NODE_ENV === "production" || process.env.REQUIRE_AUTH === "true"
  )
}

exports.middleware = function middleware(req, res, next) {
  try {
    const token = exports._getToken(req)
    res.locals.payload = exports._verifyToken(token)
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

const jwt = require("jsonwebtoken")
const keystoreBuilders = require("./keystoreBuilders")
const UnauthorizedError = require("./unauthorizedError")

//
// private methods
//

function _maxAge() {
  return process.env.MAX_JWT_AGE || "5s"
}

function _deny(response, errors) {
  response.status(401)
  response.json({ errors })
}

//
// public methods
//

exports.keystoreBuilders = keystoreBuilders

exports.extractToken = function extractToken(req) {
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
    throw new UnauthorizedError("Format is Authorization: Bearer [token]")
  }
  throw new UnauthorizedError("No authorization token was found")
}

exports.verifyToken = async function verifyToken(token, options) {
  const { keystoreBuilder } = Object.assign(
    {
      keystoreBuilder: keystoreBuilders.fromMany,
    },
    options
  )
  const keystore = await keystoreBuilder()
  const jwtOptions = {
    maxAge: _maxAge(),
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
            return [undefined, jwt.verify(token, key, jwtOptions)]
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
          return [undefined, jwt.verify(token, keystore.default, jwtOptions)]
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
            return [undefined, jwt.verify(token, keystore[kid], jwtOptions)]
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
      throw new UnauthorizedError(error, "Verification Error")
    }
    if (payload) break
  }

  if (!payload) {
    throw new UnauthorizedError("Verification Error: No matching keys")
  }
  return payload
}

exports.required = function required() {
  return (
    process.env.NODE_ENV === "production" || process.env.REQUIRE_AUTH === "true"
  )
}

exports.buildMiddleware = function buildMiddleware(options) {
  const { keystoreBuilder, payloadValidator } = Object.assign(
    {
      keystoreBuilder: keystoreBuilders.fromMany,
    },
    options
  )
  return async function _authMiddleware(req, res, next) {
    try {
      const token = exports.extractToken(req)
      const payload = await exports.verifyToken(token, { keystoreBuilder })
      if (payloadValidator !== undefined) payloadValidator(payload)
      next()
    } catch (err) {
      next(err)
    }
  }
}

exports.errorHandler = function errorHandler(err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    _deny(res, err)
  } else {
    next(err)
  }
}

exports.createToken = async function createToken(payload, options) {
  const { kid, keystoreBuilder } = Object.assign(
    {
      keystoreBuilder: keystoreBuilders.fromMany,
    },
    options
  )
  try {
    const keystore = await keystoreBuilder()
    const key =
      keystore[kid] || keystore.default || keystore[Object.keys(keystore)[0]]
    const signingKid = Object.keys(keystore).find(k => keystore[k] === key)
    return jwt.sign(payload, key, { header: { kid: signingKid } })
  } catch (err) {
    throw new UnauthorizedError(err, "Token signing failed")
  }
}

const jwt = require("jsonwebtoken");
const keystoreBuilders = require("./keystoreBuilders");
const UnauthorizedError = require("./unauthorizedError");

//
// private methods
//

function _deny(response, errors) {
  response.status(401);
  response.json({ errors });
}

//
// public methods
//

exports.keystoreBuilders = keystoreBuilders;

exports.extractToken = function extractToken(req) {
  if (req.query && req.query.token) {
    return req.query.token;
  } else if (req.headers && req.headers.authorization) {
    const parts = req.headers.authorization.split(" ");
    if (parts.length === 2) {
      const [scheme, credentials] = parts;
      if (scheme === "Bearer") {
        return credentials;
      }
    }
    throw new UnauthorizedError("Format is Authorization: Bearer [token]");
  }
  return null;
};

exports.lookupKey = async function(
  kid,
  keystoreBuilder = keystoreBuilders.fromMany
) {
  const keystore = await keystoreBuilder();
  // eslint-disable-next-line security/detect-object-injection
  return keystore[kid];
};

async function verifyTokenAndReturnPayloadAndKid(token, options) {
  // the `purpose` option aligns with the purpose field in paseto
  // (https://github.com/paragonie/paseto). we use this value to select the
  // appropriate subset of algorithms to support when verifying the token.
  //
  // * a value of "local" (the default here) indicates that the key from the
  //   keystore is a shared secret and is intended to be used with a symmetric
  //   HMAC algorithm such as HS512.
  //
  // * a value of "public" indicates that the key from the keystore is a public
  //   key and is intended to be used with an asymmetric algorithm such as ES512.
  //
  // note that this does not work for a situation where a caller's clients are
  // migrating from hmac to an asymmetric algorithm. in future work we'll want
  // to address that by attaching this value to the key in the keystore instead
  // of to the call site.
  const { keystoreBuilder, purpose } = Object.assign(
    {
      keystoreBuilder: keystoreBuilders.fromMany,
      purpose: "local"
    },
    options
  );
  let { kid } = options || {};

  let algorithms = [];
  switch (purpose) {
    case "local":
      algorithms = ["HS512"];
      break;
    case "public":
      algorithms = ["ES512"];
      break;
  }

  const keystore = await keystoreBuilder();
  const decoded = jwt.decode(token, { complete: true });
  const jwtOptions = { algorithms };
  // if the token has no expiration claim, use the default max age
  if (decoded && decoded.payload && decoded.payload.exp === undefined) {
    jwtOptions.maxAge = process.env.MAX_JWT_AGE;
  }

  if (decoded && decoded.header && decoded.header.kid) {
    if (kid && decoded.header.kid !== kid) {
      throw new UnauthorizedError(
        "Verification Error: KID doesn't match header"
      );
    } else {
      // if header specifies a kid, decode with that, without allowing fallback
      // searching to other keys
      kid = decoded.header.kid;
    }
  }

  // try verifying with a specific key. key-specific errors (lookup failure or
  // signature failure) are returned not thrown, so the caller can decide
  // whether to try another key. other key-agnostic errors are thrown not
  // returned. all errors, thrown or returned, are wrapped in an
  // UnauthorizedError.
  const verifyWithKid = kid => {
    if (!keystore.hasOwnProperty(kid)) {
      const err = new UnauthorizedError("Verification Error: Unknown KID");
      return [err, undefined];
    }
    try {
      // eslint-disable-next-line security/detect-object-injection
      const payload = jwt.verify(token, keystore[kid], jwtOptions);
      return [undefined, payload];
    } catch (err) {
      const keySpecific = err.message === "invalid signature";
      err = new UnauthorizedError(err, "Verification Error");
      if (!keySpecific) {
        throw err;
      }
      return [err, undefined];
    }
  };

  if (kid) {
    // which kid to verify with known, use it without searching. on a
    // key-specific error, throw it since there are no other keys to try
    const [err, payload] = verifyWithKid(kid);
    if (err) {
      throw err;
    }
    return [payload, kid];
  }

  // don't know which kid to use, try for any that matches
  // default first for common case efficiency
  if (keystore.hasOwnProperty("default")) {
    const [err, payload] = verifyWithKid("default");
    if (!err) {
      return [payload, "default"];
    }
  }

  for (const kid in keystore) {
    if (kid !== "default" && keystore.hasOwnProperty(kid)) {
      const [err, payload] = verifyWithKid(kid);
      if (!err) {
        return [payload, kid];
      }
    }
  }

  throw new UnauthorizedError("Verification Error: No matching keys");
}

async function verifyTokenAndReturnKid(token, options) {
  const [_, kid] = await verifyTokenAndReturnPayloadAndKid(token, options);
  return kid;
}

exports.verifyToken = async function verifyToken(token, options) {
  const [payload, _] = await verifyTokenAndReturnPayloadAndKid(token, options);
  return payload;
};

exports.required = function required() {
  if (process.env.REQUIRE_AUTH) {
    return (
      process.env.REQUIRE_AUTH.toLowerCase() !== "false" &&
      process.env.REQUIRE_AUTH !== "0"
    );
  }
  return process.env.NODE_ENV === "production";
};

exports.buildMiddleware = function buildMiddleware(options) {
  const { keystoreBuilder, isRequired, purpose } = Object.assign(
    {
      keystoreBuilder: keystoreBuilders.fromMany,
      purpose: "local",
      isRequired: exports.required()
    },
    options
  );
  return async function _authMiddleware(req, res, next) {
    try {
      const token = exports.extractToken(req);
      if (token) {
        res.locals.JWTPayload = jwt.decode(token);
        if (isRequired) {
          res.locals.JWTVerifyingKid = await verifyTokenAndReturnKid(token, {
            keystoreBuilder,
            purpose
          });
        }
      } else if (isRequired) {
        throw new UnauthorizedError("JWT is required");
      }
      next();
    } catch (err) {
      next(err);
    }
  };
};

exports.errorHandler = function errorHandler(err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    _deny(res, err);
  } else {
    next(err);
  }
};

exports.createToken = async function createToken(payload, options) {
  const { kid, keystoreBuilder, algorithm } = Object.assign(
    {
      keystoreBuilder: keystoreBuilders.fromMany,
      algorithm: "HS512"
      // ES512 is more secure, but default to symmetric for simplicity
    },
    options
  );
  try {
    const keystore = await keystoreBuilder();
    const key =
      // eslint-disable-next-line security/detect-object-injection
      keystore[kid] || keystore.default || keystore[Object.keys(keystore)[0]];
    // eslint-disable-next-line security/detect-object-injection
    const signingKid = Object.keys(keystore).find(k => keystore[k] === key);
    return jwt.sign(payload, key, { algorithm, header: { kid: signingKid } });
  } catch (err) {
    throw new UnauthorizedError(err, "Token signing failed");
  }
};

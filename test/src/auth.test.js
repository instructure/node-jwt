const { expect, expectRejection } = require("../chai");
const sinon = require("sinon");
const stubEnv = require("../stubEnv");
const auth = require("../../src/auth");
const UnauthorizedError = require("../../src/unauthorizedError");
const jwt = require("jsonwebtoken");

// We disallow the HS256 algorithm for security reasons.
// `jwt` uses this algorithm by default; let's set a new default
// here and not worry about it later.
// (we can still override this default by passing in an `options`
// with an `algorithm` key)
const _raw_sign = jwt.sign;
jwt.sign = function sign(payload, secret, options) {
  options = Object.assign(
    {
      algorithm: "HS512"
    },
    options
  );
  return _raw_sign(payload, secret, options);
};

function hoursFromNow(hours) {
  return +Date.now() / 1000 + 60 * 60 * hours;
}

describe("API authorization", function() {
  describe("required", function() {
    stubEnv();

    it("defaults to false in test env", function() {
      process.env.NODE_ENV = "test";
      delete process.env.REQUIRE_AUTH;
      expect(auth.required()).to.be.false;
    });

    it("can be forced to true", function() {
      process.env.NODE_ENV = "test";
      process.env.REQUIRE_AUTH = "true";
      expect(auth.required()).to.be.true;
    });

    describe("responds to the specific value of REQUIRE_AUTH", function() {
      it("setting to '0' forces auth off", function() {
        process.env.NODE_ENV = "test";
        process.env.REQUIRE_AUTH = "0";
        expect(auth.required()).to.be.false;
      });

      it("setting to 'false' forces auth off", function() {
        process.env.NODE_ENV = "test";
        process.env.REQUIRE_AUTH = "false";
        expect(auth.required()).to.be.false;
      });

      it("setting to 'false' (case-insensitve) forces auth off", function() {
        process.env.NODE_ENV = "test";
        process.env.REQUIRE_AUTH = "fAlSe";
        expect(auth.required()).to.be.false;
      });

      it("setting to anything else forces auth on", function() {
        process.env.NODE_ENV = "test";
        process.env.REQUIRE_AUTH = "asdf";
        expect(auth.required()).to.be.true;
      });
    });

    it("defaults false for development", function() {
      process.env.NODE_ENV = "development";
      delete process.env.REQUIRE_AUTH;
      expect(auth.required()).to.be.false;
    });

    it("can be forced on for development", function() {
      process.env.NODE_ENV = "development";
      process.env.REQUIRE_AUTH = "true";
      expect(auth.required()).to.be.true;
    });

    it("defaults true for production", function() {
      process.env.NODE_ENV = "production";
      delete process.env.REQUIRE_AUTH;
      expect(auth.required()).to.be.true;
    });

    it("can be forced on for production", function() {
      process.env.NODE_ENV = "production";
      process.env.REQUIRE_AUTH = "false";
      expect(auth.required()).to.be.false;
    });
  });

  describe("max age", function() {
    stubEnv();

    const payload = { a: 1, iat: hoursFromNow(-24) };
    beforeEach(() => {
      process.env.AUTH_SECRET = Buffer.from("sUpEr SecReT!1!").toString(
        "base64"
      );
      process.env.MAX_JWT_AGE = "12h";
    });

    it("fails if MAX_JWT_AGE is shorter than `now - iat`", async function() {
      const token = await auth.createToken(payload);

      const err = await expectRejection(auth.verifyToken(token));
      expect(err.name).to.equal("UnauthorizedError");
    });

    it("ignores MAX_JWT_AGE if token has an exp claim", async function() {
      payload.exp = hoursFromNow(24);
      const token = await auth.createToken(payload);

      const result = await auth.verifyToken(token);
      expect(result).to.include(payload);
    });
    it("never expires if token has no exp claim and MAX_JWT_AGE is not set", async function() {
      delete process.env.MAX_JWT_AGE;

      const token = await auth.createToken(payload);

      const result = await auth.verifyToken(token);
      expect(result).to.include(payload);
    });
  });

  describe("verifyToken", function() {
    const secret = Buffer.from("sUpEr SecReT!1!");
    const payload = { a: 1 };

    it("returns the JWT payload", async function() {
      const keystoreBuilder = () => {
        return { default: secret };
      };

      const token = await auth.createToken(payload, { keystoreBuilder });
      const result = await auth.verifyToken(token, { keystoreBuilder });
      expect(result).to.include(payload);
    });

    it("rejects with 'none' algorithm", async function() {
      const keystoreBuilder = () => {
        return { default: secret };
      };

      const token = await auth.createToken(payload, {
        algorithm: "none",
        keystoreBuilder
      });
      const err = await expectRejection(
        auth.verifyToken(token, { keystoreBuilder })
      );
      expect(err.name).to.equal("UnauthorizedError");
    });

    it("verifies with HS512 algorithm", async function() {
      const keystoreBuilder = () => {
        return { default: secret };
      };

      const token = await auth.createToken(payload, {
        algorithm: "HS512",
        keystoreBuilder
      });
      const result = await auth.verifyToken(token, { keystoreBuilder });
      expect(result).to.include(payload);
    });

    it("verifies with ES512 algorithm", async function() {
      // this is a random keypair generated just for this test
      const publicKey =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEXcjKOpKzx4Ij8vwndnjzpPyvNGZpeTLS\n" +
        "0SG7kAmbGOjd1ivK/AsHy6GzXeNwo6LAr80wYYBOVrWmbW5O5whXcQ==\n" +
        "-----END PUBLIC KEY-----\n";

      const privateKey =
        "-----BEGIN EC PRIVATE KEY-----\n" +
        "MHQCAQEEIDj7vlqvdVuNC5gvlEAyPmaZrKtZ/1Eket3XSL2F9vewoAcGBSuBBAAK\n" +
        "oUQDQgAEXcjKOpKzx4Ij8vwndnjzpPyvNGZpeTLS0SG7kAmbGOjd1ivK/AsHy6Gz\n" +
        "XeNwo6LAr80wYYBOVrWmbW5O5whXcQ==\n" +
        "-----END EC PRIVATE KEY-----\n";

      const signingKeystoreBuilder = () => ({ default: privateKey });
      const verifyingKeystoreBuilder = () => ({ default: publicKey });

      const token = await auth.createToken(payload, {
        algorithm: "ES512",
        keystoreBuilder: signingKeystoreBuilder
      });
      const result = await auth.verifyToken(token, {
        keystoreBuilder: verifyingKeystoreBuilder,
        purpose: "public"
      });
      expect(result).to.include(payload);
    });

    it("rejects HMAC signature when expecting asymmetric algorithm", async function() {
      const publicKey =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEXcjKOpKzx4Ij8vwndnjzpPyvNGZpeTLS\n" +
        "0SG7kAmbGOjd1ivK/AsHy6GzXeNwo6LAr80wYYBOVrWmbW5O5whXcQ==\n" +
        "-----END PUBLIC KEY-----\n";

      const keystoreBuilder = () => ({ default: publicKey });

      const token = await auth.createToken(payload, {
        algorithm: "HS512",
        keystoreBuilder
      });
      const err = await expectRejection(
        auth.verifyToken(token, { keystoreBuilder, purpose: "public" })
      );
      expect(err.name).to.equal("UnauthorizedError");
    });

    it("uses secret with kid if kid is included in header", async function() {
      const keystoreBuilder = () => {
        return { kid: secret };
      };

      const token = await auth.createToken(payload, {
        kid: "kid",
        keystoreBuilder
      });
      const result = await auth.verifyToken(token, { keystoreBuilder });
      expect(result).to.include(payload);
    });

    it("rejects if verification with kid in header doesn't work", async function() {
      // signing will use otherSecret, then verifying with the same kid will
      // use secret, so they shouldn't match. but when verifying the default
      // key would hold otherSecret -- but we want to assert we don't try it!
      const otherSecret = Buffer.from("a DIFFERENT sUpEr SecReT!1!");
      const kid = "specificKid";
      const createKeystoreBuilder = () => {
        return {
          [kid]: otherSecret,
          default: secret
        };
      };
      const verifyKeystoreBuilder = () => {
        return {
          [kid]: secret,
          default: otherSecret
        };
      };

      const token = await auth.createToken(payload, {
        kid,
        keystoreBuilder: createKeystoreBuilder
      });
      const err = await expectRejection(
        auth.verifyToken(token, {
          keystoreBuilder: verifyKeystoreBuilder
        })
      );

      expect(err.name).to.equal("UnauthorizedError");
    });

    it("rejects if verification by specific kid requested and that doesn't match the kid in header", async function() {
      // all secrets the same so that it could work if we weren't enforcing kids
      const headerKid = "headerKid";
      const requestedKid = "requestedKid";
      const keystoreBuilder = () => {
        return {
          [headerKid]: secret,
          [requestedKid]: secret,
          default: secret
        };
      };

      const token = await auth.createToken(payload, {
        kid: headerKid,
        keystoreBuilder
      });
      const err = await expectRejection(
        auth.verifyToken(token, {
          kid: requestedKid,
          keystoreBuilder
        })
      );

      expect(err.name).to.equal("UnauthorizedError");
      expect(err.message).to.match(/KID doesn't match header/);
    });

    it("doesn't fall back to other keys if verification with requested kid fails", async function() {
      const otherSecret = "difFerENt SecReT!1!";
      const kid = "requestedKid";
      const keystoreBuilder = () => {
        return {
          [kid]: otherSecret,
          default: secret
        };
      };

      // as if `await auth.createToken(payload, { keystoreBuilder })`, but we
      // don't want `{ kid: "default" }` in the header
      const token = jwt.sign(payload, secret, { algorithm: "HS512" });
      const err = await expectRejection(
        auth.verifyToken(token, { kid, keystoreBuilder })
      );

      expect(err.name).to.equal("UnauthorizedError");
      expect(err.message).to.match(/Verification Error/);
    });

    it("tries all secrets if no default or kid", async function() {
      const keystoreBuilder = () => {
        return { other: secret };
      };

      const token = await auth.createToken(payload, { keystoreBuilder });
      const result = await auth.verifyToken(token, { keystoreBuilder });
      expect(result).to.include(payload);
    });
  });

  describe("extractToken", function() {
    let request;
    beforeEach(function() {
      request = { headers: {}, query: {} };
    });

    it("returns null if no token found", function() {
      expect(auth.extractToken(request)).to.be.null;
    });

    it("finds token in authorization header", function() {
      request.headers.authorization = "Bearer token";
      expect(auth.extractToken(request)).to.equal("token");
    });

    it("finds token in query string", function() {
      request.query.token = "token";
      expect(auth.extractToken(request)).to.equal("token");
    });

    it("prefers token in query string over token in header", function() {
      request.query.token = "correct token";
      request.headers.authorization = "other token";
      expect(auth.extractToken(request)).to.equal("correct token");
    });
  });

  describe("buildMiddleware", function() {
    const secret = "sUpEr SecReT!1!";
    const payload = { a: 1 };
    const keystoreBuilder = () => {
      return { default: Buffer.from(secret) };
    };
    stubEnv();

    let request, token, middleware, response;
    beforeEach(function() {
      process.env.REQUIRE_AUTH = "true";
      middleware = auth.buildMiddleware({ keystoreBuilder });
      token = jwt.sign(payload, secret);
      request = { headers: {}, query: {} };
      response = { locals: {} };
    });

    async function expectMiddlewareSuccess(request, response) {
      next = sinon.spy();
      await middleware(request, response, next);
      expect(next).to.have.been.calledOnce;
      expect(next.firstCall.args[0]).to.be.undefined;
    }

    async function expectMiddlewareFailure(request, response) {
      next = sinon.spy();
      await middleware(request, response, next);
      expect(next).to.have.been.calledOnce;
      const err = next.firstCall.args[0];
      expect(err).not.to.be.undefined;
      return err;
    }

    it("fails if token is malformed", async function() {
      request.query.token = "not-a-jwt";
      const err = await expectMiddlewareFailure(request, response);
      expect(err.name).to.equal("UnauthorizedError");
      expect(err.JWTError).to.equal("jwt malformed");
    });

    it("fails if the authorization header isn't 'Bearer <token>'", async function() {
      request.headers.authorization = "some other scheme";
      const err = await expectMiddlewareFailure(request, response);
      expect(err.name).to.equal("UnauthorizedError");
      expect(err.message).to.match(/Format is Authorization: Bearer/);
    });

    it("fails if token doesn't match secret", async function() {
      request.query.token = jwt.sign({}, "wrong secret oh noes");
      const err = await expectMiddlewareFailure(request, response);
      expect(err.name).to.equal("UnauthorizedError");
      expect(err.message).to.match(/No matching keys/);
    });

    it("fails if token is expired", async function() {
      request.query.token = jwt.sign(
        { iat: hoursFromNow(-4), exp: hoursFromNow(-2) },
        secret
      );
      const err = await expectMiddlewareFailure(request, response);
      expect(err.name).to.equal("UnauthorizedError");
      expect(err.JWTError).to.equal("jwt expired");
    });

    it("fails if no signature algorithm provided", async function() {
      request.query.token = jwt.sign({}, secret, { algorithm: "none" });
      const err = await expectMiddlewareFailure(request, response);
      expect(err.name).to.equal("UnauthorizedError");
      expect(err.JWTError).to.equal("jwt signature is required");
    });

    it("fails if no token provided and auth is required", async function() {
      const err = await expectMiddlewareFailure(request, response);
      expect(err.name).to.equal("UnauthorizedError");
      expect(err.message).to.match(/JWT is required/);
    });

    it("accepts a valid token signed with secret", async function() {
      request.query.token = token;
      await expectMiddlewareSuccess(request, response);
      expect(response.locals.JWTPayload).to.include(payload);
    });

    it("sets the JWTVerifyingKid on the response on success", async function() {
      request.query.token = token;
      await expectMiddlewareSuccess(request, response);
      expect(response.locals.JWTVerifyingKid).to.equal("default");
    });

    describe("when auth is not required", function() {
      beforeEach(function() {
        middleware = auth.buildMiddleware({ isRequired: false });
      });

      it("accepts if no token provided", async function() {
        await expectMiddlewareSuccess(request, response);
      });

      it("still sets payload", async function() {
        request.query.token = token;
        await expectMiddlewareSuccess(request, response);
        expect(response.locals.JWTPayload).to.include(payload);
      });

      describe("and no secret is set", function() {
        beforeEach(function() {
          middleware = auth.buildMiddleware({
            keystoreBuilder: () => {},
            isRequired: false
          });
        });

        it("accepts if no token provided", async function() {
          await expectMiddlewareSuccess(request, response);
          expect(response.locals.JWTPayload).to.be.undefined;
        });

        it("still sets payload", async function() {
          request.query.token = token;
          await expectMiddlewareSuccess(request, response);
          expect(response.locals.JWTPayload).to.include(payload);
        });
      });
    });
  });

  describe("errorHandler", function() {
    const request = {};
    let response, next;
    beforeEach(function() {
      response = { status: sinon.spy(), json: sinon.spy() };
      next = sinon.spy();
    });

    it("ignores non-authorization errors", function() {
      const error = new Error("not relevant");
      auth.errorHandler(error, request, response, next);
      expect(next).to.be.calledWith(error);
    });

    it("denies authorization errors with details", function() {
      const error = new UnauthorizedError("code", {
        message: "relevant"
      });
      auth.errorHandler(error, request, response, next);
      expect(response.status).to.be.calledWith(401);
      expect(response.json).to.be.calledWithMatch({ errors: error });
    });

    it("halts request when denying errors", function() {
      const error = new UnauthorizedError("code", {
        message: "relevant"
      });
      auth.errorHandler(error, request, response, next);
      expect(next).not.to.be.called;
    });
  });

  describe("createToken", function() {
    const secret = Buffer.from("sUpEr SecReT!1!");

    it("fails if buildKeystore fails", async function() {
      async function keystoreBuilder() {
        throw new Error("wahhh");
      }

      await expectRejection(auth.createToken({}, { keystoreBuilder }));
    });

    it("creates a token with given payload", async function() {
      const keystoreBuilder = () => {
        return { kid: secret };
      };
      const payload = { a: 1 };
      const token = await auth.createToken(payload, { keystoreBuilder });
      const decoded = jwt.decode(token);
      expect(decoded).to.include(payload);
    });

    it("creates a token signed with given kid", async function() {
      const keystoreBuilder = () => {
        return { kid: secret };
      };
      const token = await auth.createToken({}, { kid: "kid", keystoreBuilder });
      const decoded = jwt.decode(token, { complete: true });
      expect(decoded.header.kid).to.equal("kid");
    });
  });

  describe("lookupKey", function() {
    const secret = "sUpEr SecReT!1!";

    stubEnv();

    it("finds the key by kid in the keystore from the provided builder", async function() {
      const keystoreBuilder = () => {
        return { kid: secret };
      };
      const key = await auth.lookupKey("kid", keystoreBuilder);
      expect(key.toString("UTF-8")).to.equal(secret);
    });

    it("defaults to looking in the keystore from the fromMany builder", async function() {
      process.env.AUTH_SECRET = Buffer.from(secret).toString("base64");
      const key = await auth.lookupKey("default");
      expect(key.toString("UTF-8")).to.equal(secret);
    });
  });
});

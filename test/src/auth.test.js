const { expect, expectRejection } = require("../chai")
const sinon = require("sinon")
const stubEnv = require("../stubEnv")
const auth = require("../../src/auth")
const UnauthorizedError = require("../../src/unauthorizedError")
const jwt = require("jsonwebtoken")

describe("API authorization", function() {
  describe("required", function() {
    stubEnv()

    it("defaults false for test", function() {
      process.env.NODE_ENV = "test"
      delete process.env.REQUIRE_AUTH
      expect(auth.required()).to.be.false
    })

    it("can be forced on for test", function() {
      process.env.NODE_ENV = "test"
      process.env.REQUIRE_AUTH = "true"
      expect(auth.required()).to.be.true
    })

    it("defaults false for development", function() {
      process.env.NODE_ENV = "development"
      delete process.env.REQUIRE_AUTH
      expect(auth.required()).to.be.false
    })

    it("can be forced on for development", function() {
      process.env.NODE_ENV = "development"
      process.env.REQUIRE_AUTH = "true"
      expect(auth.required()).to.be.true
    })

    it("defaults true for production", function() {
      process.env.NODE_ENV = "production"
      delete process.env.REQUIRE_AUTH
      expect(auth.required()).to.be.true
    })

    it("can't be forced off for production", function() {
      process.env.NODE_ENV = "production"
      process.env.REQUIRE_AUTH = "false"
      expect(auth.required()).to.be.true
    })
  })

  describe("max age", function() {
    stubEnv()

    const secret = Buffer.from("sUpEr SecReT!1!").toString("base64")
    const tenSecondsAgo = +Date.now() / 1000 - 10
    const payload = { a: 1, iat: tenSecondsAgo }

    it("gets value from environment", async function() {
      process.env.MAX_JWT_AGE = "30s"
      process.env.AUTH_SECRET = secret

      const token = await auth.createToken(payload)

      const result = await auth.verifyToken(token)
      expect(result).to.include(payload)
    })

    it("defaults to 5 seconds", async function() {
      delete process.env.MAX_JWT_AGE
      process.env.AUTH_SECRET = secret

      const token = await auth.createToken(payload)

      const err = await expectRejection(auth.verifyToken(token))
      expect(err.name).to.equal("UnauthorizedError")
    })
  })

  describe("verifyToken", function() {
    const secret = Buffer.from("sUpEr SecReT!1!")
    const payload = { a: 1 }

    it("returns the JWT payload", async function() {
      const keystoreBuilder = () => {
        return { default: secret }
      }

      const token = await auth.createToken(payload, { keystoreBuilder })
      const result = await auth.verifyToken(token, { keystoreBuilder })
      expect(result).to.include(payload)
    })

    it("uses secret with kid if kid is included in header", async function() {
      const keystoreBuilder = () => {
        return { kid: secret }
      }

      const token = await auth.createToken(payload, {
        kid: "kid",
        keystoreBuilder,
      })
      const result = await auth.verifyToken(token, { keystoreBuilder })
      expect(result).to.include(payload)
    })

    it("tries all secrets if no default or kid", async function() {
      const keystoreBuilder = () => {
        return { other: secret }
      }

      const token = await auth.createToken(payload, { keystoreBuilder })
      const result = await auth.verifyToken(token, { keystoreBuilder })
      expect(result).to.include(payload)
    })

    it("verifies if given kid doesn't exist", async function() {
      const keystoreBuilder = () => {
        return { default: secret }
      }

      const token = await auth.createToken(payload, {
        kid: "kid",
        keystoreBuilder,
      })
      const result = await auth.verifyToken(token, { keystoreBuilder })
      expect(result).to.include(payload)
    })
  })

  describe("extractToken", function() {
    let request
    beforeEach(function() {
      request = { headers: {}, query: {} }
    })

    it("finds token in authorization header", function() {
      request.headers.authorization = "Bearer token"
      expect(auth.extractToken(request)).to.equal("token")
    })

    it("finds token in query string", function() {
      request.query.token = "token"
      expect(auth.extractToken(request)).to.equal("token")
    })

    it("prefers token in query string over token in header", function() {
      request.query.token = "correct token"
      request.headers.authorization = "other token"
      expect(auth.extractToken(request)).to.equal("correct token")
    })
  })

  describe("buildMiddleware", function() {
    const secret = "sUpEr SecReT!1!"
    const response = { locals: {} }
    const keystoreBuilder = () => {
      return { default: Buffer.from(secret) }
    }
    let request, token, middleware
    beforeEach(function() {
      middleware = auth.buildMiddleware({ keystoreBuilder })
      token = jwt.sign({}, secret)
      request = { headers: {}, query: {} }
    })

    it("fails if no token provided", function(done) {
      middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.message).to.match(/No authorization token was found/)
        done()
      })
    })

    it("fails if token is malformed", function(done) {
      request.query.token = "not-a-jwt"
      middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.JWTError).to.equal("jwt malformed")
        done()
      })
    })

    it("fails if the authorization header isn't 'Bearer <token>'", function(
      done
    ) {
      request.headers.authorization = "some other scheme"
      middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.message).to.match(/Format is Authorization: Bearer/)
        done()
      })
    })

    it("fails if token doesn't match secret", function(done) {
      request.query.token = jwt.sign({}, "wrong secret oh noes")
      middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.message).to.match(/No matching keys/)
        done()
      })
    })

    it("fails if token is expired", function(done) {
      const twoDaysAgo = +Date.now() / 1000 - 172800
      request.query.token = jwt.sign({ iat: twoDaysAgo }, secret)
      middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.JWTError).to.equal("maxAge exceeded")
        done()
      })
    })

    it("fails if no signature algorithm provided", function(done) {
      request.query.token = jwt.sign({}, secret, { algorithm: "none" })
      middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.JWTError).to.equal("jwt signature is required")
        done()
      })
    })

    it("accepts a valid token signed with secret", function(done) {
      request.query.token = token
      middleware(request, response, done)
    })

    describe("payloadValidator", function() {
      function payloadValidator(payload) {
        if (!payload.isValid) throw new Error("not today")
      }

      beforeEach(() => {
        middleware = auth.buildMiddleware({ keystoreBuilder, payloadValidator })
      })

      it("rejects valid JWTs that fail payloadValidator", function(done) {
        token = jwt.sign({ isValid: false }, secret)
        request.query.token = token

        middleware(request, response, err => {
          expect(err.message).to.equal("not today")
          done()
        })
      })

      it("accepts JWTs that pass payloadValidator", function(done) {
        token = jwt.sign({ isValid: true }, secret)
        request.query.token = token

        middleware(request, response, done)
      })
    })
  })

  describe("errorHandler", function() {
    const request = {}
    let response, next
    beforeEach(function() {
      response = { status: sinon.spy(), json: sinon.spy() }
      next = sinon.spy()
    })

    it("ignores non-authorization errors", function() {
      const error = new Error("not relevant")
      auth.errorHandler(error, request, response, next)
      expect(next).to.be.calledWith(error)
    })

    it("denies authorization errors with details", function() {
      const error = new UnauthorizedError("code", {
        message: "relevant",
      })
      auth.errorHandler(error, request, response, next)
      expect(response.status).to.be.calledWith(401)
      expect(response.json).to.be.calledWithMatch({ errors: error })
    })

    it("halts request when denying errors", function() {
      const error = new UnauthorizedError("code", {
        message: "relevant",
      })
      auth.errorHandler(error, request, response, next)
      expect(next).not.to.be.called
    })
  })

  describe("createToken", function() {
    const secret = Buffer.from("sUpEr SecReT!1!")

    it("fails if buildKeystore fails", async function() {
      const keystoreBuilder = () => {
        throw new Error("wahhh")
      }

      await expectRejection(auth.createToken({ keystoreBuilder }))
    })

    it("creates a token with given payload", async function() {
      const keystoreBuilder = () => {
        return { kid: secret }
      }
      const payload = { a: 1 }
      const token = await auth.createToken(payload, { keystoreBuilder })
      const decoded = jwt.decode(token)
      expect(decoded).to.include(payload)
    })

    it("creates a token signed with given kid", async function() {
      const keystoreBuilder = () => {
        return { kid: secret }
      }
      const token = await auth.createToken({}, { kid: "kid", keystoreBuilder })
      const decoded = jwt.decode(token, { complete: true })
      expect(decoded.header.kid).to.equal("kid")
    })
  })
})

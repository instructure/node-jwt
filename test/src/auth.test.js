const { expect, expectRejection } = require("chai")
const sinon = require("sinon")
const stubEnv = require("../stubEnv")
const auth = require("../../src/auth")
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

  describe("_buildKeystore", function() {
    describe("from AUTH_SECRET", function() {
      stubEnv()
      beforeEach(function() {
        delete process.env.CONSUL_JWT_SECRET_PREFIX
      })

      it("fails when secret isn't set", function() {
        delete process.env.AUTH_SECRET
        expect(auth._buildKeystore).to.throw
      })

      it("fails when secret is blank", function() {
        process.env.AUTH_SECRET = ""
        expect(auth._buildKeystore).to.throw
      })

      it("extracts default secret", async function() {
        const buffer = Buffer.from("sUpEr SecReT!1!")
        const secret = buffer.toString("base64")
        process.env.AUTH_SECRET = secret
        const keystore = await auth._buildKeystore()
        expect(keystore).to.deep.equal({
          default: buffer,
        })
      })

      it("extracts keyed secrets", async function() {
        const b1 = Buffer.from("secret1")
        const b2 = Buffer.from("secret2")
        const s1 = b1.toString("base64")
        const s2 = b2.toString("base64")
        process.env.AUTH_SECRET = `secret1:${s1} secret2:${s2}`
        const keystore = await auth._buildKeystore()
        expect(keystore).to.deep.equal({
          secret1: b1,
          secret2: b2,
        })
      })

      it("extracts default + keyed secrets", async function() {
        const b1 = Buffer.from("secret1")
        const b2 = Buffer.from("secret2")
        const s1 = b1.toString("base64")
        const s2 = b2.toString("base64")
        process.env.AUTH_SECRET = `${s1} secret2:${s2}`
        const keystore = await auth._buildKeystore()
        expect(keystore).to.deep.equal({
          default: b1,
          secret2: b2,
        })
      })

      it("only extracts a single default secret", async function() {
        const b1 = Buffer.from("secret1")
        const b2 = Buffer.from("secret2")
        const s1 = b1.toString("base64")
        const s2 = b2.toString("base64")
        process.env.AUTH_SECRET = `${s1} ${s2}`
        const keystore = await auth._buildKeystore()
        expect(keystore).to.deep.equal({
          default: b2,
        })
      })
    })

    describe("from Consul", function() {})
  })

  describe("_deny", function() {
    let response
    beforeEach(() => {
      response = {
        status: sinon.spy(),
        json: sinon.spy(),
      }
    })

    it("replies with a 401 status", function() {
      auth._deny(response, {})
      expect(response.status).to.be.calledWith(401)
    })

    it("includes errors in the json body", function() {
      const errors = { authorization: "invalid" }
      auth._deny(response, errors)
      expect(response.json).to.be.calledWith({ errors })
    })
  })

  describe("_maxAge", function() {
    stubEnv()

    it("gets value from environment", function() {
      process.env.MAX_JWT_AGE = "heyyo"
      expect(auth._maxAge()).to.equal("heyyo")
    })

    it("defaults to 5 seconds", function() {
      delete process.env.MAX_JWT_AGE
      expect(auth._maxAge()).to.equal("5s")
    })
  })

  describe("_verifyToken", function() {
    const secret = Buffer.from("sUpEr SecReT!1!")

    afterEach(function() {
      auth._buildKeystore.restore()
    })

    it("returns the JWT payload", async function() {
      sinon.stub(auth, "_buildKeystore").returns({ default: secret })

      const payload = { a: 1 }
      const token = await auth.createToken(payload)
      const result = await auth._verifyToken(token)
      expect(result).to.include(payload)
    })

    it("uses secret with kid if kid is included in header", async function() {
      sinon.stub(auth, "_buildKeystore").returns({ kid: secret })

      const token = await auth.createToken({}, "kid")
      const result = await auth._verifyToken(token)
      expect(result).to.not.be.undefined
    })

    it("tries all secrets if no default or kid", async function() {
      sinon.stub(auth, "_buildKeystore").returns({ other: secret })

      const token = await auth.createToken({})
      const result = await auth._verifyToken(token)
      expect(result).to.not.be.undefined
    })

    it("verifies if given kid doesn't exist", async function() {
      sinon.stub(auth, "_buildKeystore").returns({ default: secret })

      const token = await auth.createToken({}, "kid")
      const result = await auth._verifyToken(token)
      expect(result).to.not.be.undefined
    })
  })

  describe("_getToken", function() {
    let request
    beforeEach(function() {
      request = { headers: {}, query: {} }
    })

    it("finds token in authorization header", function() {
      request.headers.authorization = "Bearer token"
      expect(auth._getToken(request)).to.equal("token")
    })

    it("finds token in query string", function() {
      request.query.token = "token"
      expect(auth._getToken(request)).to.equal("token")
    })

    it("prefers token in query string over token in header", function() {
      request.query.token = "correct token"
      request.headers.authorization = "other token"
      expect(auth._getToken(request)).to.equal("correct token")
    })
  })

  describe("middleware", function() {
    const secret = "sUpEr SecReT!1!"
    const response = { locals: {} }
    let request, token
    beforeEach(function() {
      sinon
        .stub(auth, "_buildKeystore")
        .returns({ default: Buffer.from(secret) })
      token = jwt.sign({}, secret)
      request = { headers: {}, query: {} }
    })

    afterEach(function() {
      auth._buildKeystore.restore()
    })

    it("fails if no token provided", function(done) {
      auth.middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.message).to.match(/No authorization token was found/)
        done()
      })
    })

    it("fails if token is malformed", function(done) {
      request.query.token = "not-a-jwt"
      auth.middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.JWTError).to.equal("jwt malformed")
        done()
      })
    })

    it("fails if the authorization header isn't 'Bearer <token>'", function(
      done
    ) {
      request.headers.authorization = "some other scheme"
      auth.middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.message).to.match(/Format is Authorization: Bearer/)
        done()
      })
    })

    it("fails if token doesn't match secret", function(done) {
      request.query.token = jwt.sign({}, "wrong secret oh noes")
      auth.middleware(request, response, err => {
        expect(err.message).to.match(/No matching keys/)
        done()
      })
    })

    it("fails if token is expired", function(done) {
      const twoDaysAgo = +Date.now() / 1000 - 172800
      request.query.token = jwt.sign({ iat: twoDaysAgo }, secret)
      auth.middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.JWTError).to.equal("maxAge exceeded")
        done()
      })
    })

    it("fails if no signature algorithm provided", function(done) {
      request.query.token = jwt.sign({}, secret, { algorithm: "none" })
      auth.middleware(request, response, err => {
        expect(err.name).to.equal("UnauthorizedError")
        expect(err.JWTError).to.equal("jwt signature is required")
        done()
      })
    })

    it("accepts a valid token signed with secret", function(done) {
      request.query.token = token
      auth.middleware(request, response, err => {
        expect(err).to.be.undefined
        done()
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
      const error = new auth.UnauthorizedError("code", {
        message: "relevant",
      })
      auth.errorHandler(error, request, response, next)
      expect(response.status).to.be.calledWith(401)
      expect(response.json).to.be.calledWithMatch({ errors: error })
    })

    it("halts request when denying errors", function() {
      const error = new auth.UnauthorizedError("code", {
        message: "relevant",
      })
      auth.errorHandler(error, request, response, next)
      expect(next).not.to.be.called
    })
  })

  describe("createToken", function() {
    const secret = Buffer.from("sUpEr SecReT!1!")
    beforeEach(function() {
      sinon.stub(auth, "_buildKeystore").returns({ kid: secret })
    })

    afterEach(function() {
      auth._buildKeystore.restore()
    })

    it("fails if buildKeystore fails", async function() {
      auth._buildKeystore.restore()
      sinon.stub(auth, "_buildKeystore").throws()

      expectRejection(auth.createToken())
    })

    it("creates a token with given payload", async function() {
      const payload = { a: 1 }
      const token = await auth.createToken(payload)
      const decoded = jwt.decode(token)
      expect(decoded).to.include(payload)
    })
    it("creates a token signed with given kid", async function() {
      const token = await auth.createToken({}, "kid")
      const decoded = jwt.decode(token, { complete: true })
      expect(decoded.header.kid).to.equal("kid")
    })
  })
})

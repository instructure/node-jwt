const { expect } = require("chai")
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

      it("fails when secret isn't set", function() {
        delete process.env.AUTH_SECRET
        expect(auth._buildKeystore).to.throw
      })

      it("fails when secret is blank", function() {
        process.env.AUTH_SECRET = ""
        expect(auth._buildKeystore).to.throw
      })

      it("extracts default secret", function() {
        const secret = Buffer.from("sUpEr SecReT!1!").toString("base64")
        process.env.AUTH_SECRET = secret
        expect(auth._buildKeystore()).to.deep.equal({
          default: secret,
        })
      })

      it("extracts keyed secrets", function() {
        const s1 = Buffer.from("secret1").toString("base64")
        const s2 = Buffer.from("secret2").toString("base64")
        process.env.AUTH_SECRET = `secret1:${s1} secret2:${s2}`
        expect(auth._buildKeystore()).to.deep.equal({
          secret1: s1,
          secret2: s2,
        })
      })

      it("extracts default + keyed secrets", function() {
        const s1 = Buffer.from("secret1").toString("base64")
        const s2 = Buffer.from("secret2").toString("base64")
        process.env.AUTH_SECRET = `${s1} secret2:${s2}`
        expect(auth._buildKeystore()).to.deep.equal({
          default: s1,
          secret2: s2,
        })
      })

      it("only extracts a single default secret", function() {
        const s1 = Buffer.from("secret1").toString("base64")
        const s2 = Buffer.from("secret2").toString("base64")
        process.env.AUTH_SECRET = `${s1} ${s2}`
        expect(auth._buildKeystore()).to.deep.equal({
          default: s2,
        })
      })
    })

    describe("from consul", function() {
      it("todo")
    })
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
    it("returns the JWT payload")
    it("uses the default secret if no kid is given")
    it("tries all secrets if no default or kid")
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
    const secret = Buffer.from("sUpEr SecReT!1!").toString("base64")
    const response = { locals: {} }
    let request, token
    beforeEach(function() {
      sinon.stub(auth, "_buildKeystore").returns({ default: secret })
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
    it("fails if buildKeystore fails")
    it("creates a token")
  })
})

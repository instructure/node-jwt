const { expect } = require("../chai")
const stubEnv = require("../stubEnv")
const { fromEnv } = require("../../src/keystoreBuilders")

describe("fromEnv", function() {
  stubEnv()

  it("returns blank when AUTH_SECRET is not set", async function() {
    delete process.env.AUTH_SECRET
    const keystore = await fromEnv()
    expect(keystore).to.deep.equal({})
  })

  it("returns blank when secret is blank", async function() {
    process.env.AUTH_SECRET = ""
    const keystore = await fromEnv()
    expect(keystore).to.deep.equal({})
  })

  it("extracts default secret", async function() {
    const buffer = Buffer.from("sUpEr SecReT!1!")
    const secret = buffer.toString("base64")
    process.env.AUTH_SECRET = secret
    const keystore = await fromEnv()
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
    const keystore = await fromEnv()
    expect(keystore).to.deep.equal({
      secret1: b1,
      secret2: b2,
    })
  })

  it("ignores secrets with colons", async function() {
    const buffer1 = Buffer.from("secret1")
    const buffer2 = Buffer.from("secret2")
    const secret1 = buffer1.toString("base64")
    const secret2 = buffer2.toString("base64")
    process.env.AUTH_SECRET = `kid1:${secret1} kid2:${secret2}:extrajunk`
    const keystore = await fromEnv()
    expect(keystore).to.deep.equal({
      kid1: buffer1,
    })
  })

  it("extracts default + keyed secrets", async function() {
    const b1 = Buffer.from("secret1")
    const b2 = Buffer.from("secret2")
    const s1 = b1.toString("base64")
    const s2 = b2.toString("base64")
    process.env.AUTH_SECRET = `${s1} secret2:${s2}`
    const keystore = await fromEnv()
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
    const keystore = await fromEnv()
    expect(keystore).to.deep.equal({
      default: b2,
    })
  })
})

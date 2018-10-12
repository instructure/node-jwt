const { expect } = require("../chai");
const stubEnv = require("../stubEnv");
const consul = require("../../src/consulKVStore");
const {
  fromString,
  fromEnv,
  fromConsul,
  fromMany
} = require("../../src/keystoreBuilders");

describe("fromString", function() {
  it("returns blank when secret is blank", async function() {
    const keystore = await fromString("");
    expect(keystore).to.deep.equal({});
  });

  it("extracts default secret", async function() {
    const buffer = Buffer.from("sUpEr SecReT!1!");
    const secret = buffer.toString("base64");
    const keystore = await fromString(secret);
    expect(keystore).to.deep.equal({
      default: buffer
    });
  });

  it("extracts keyed secrets", async function() {
    const b1 = Buffer.from("secret1");
    const b2 = Buffer.from("secret2");
    const s1 = b1.toString("base64");
    const s2 = b2.toString("base64");
    const keystore = await fromString(`secret1:${s1} secret2:${s2}`);
    expect(keystore).to.deep.equal({
      secret1: b1,
      secret2: b2
    });
  });

  it("ignores secrets with colons", async function() {
    const buffer1 = Buffer.from("secret1");
    const buffer2 = Buffer.from("secret2");
    const secret1 = buffer1.toString("base64");
    const secret2 = buffer2.toString("base64");
    const keystore = await fromString(
      `kid1:${secret1} kid2:${secret2}:extrajunk`
    );
    expect(keystore).to.deep.equal({
      kid1: buffer1
    });
  });

  it("extracts default + keyed secrets", async function() {
    const b1 = Buffer.from("secret1");
    const b2 = Buffer.from("secret2");
    const s1 = b1.toString("base64");
    const s2 = b2.toString("base64");
    const keystore = await fromString(`${s1} secret2:${s2}`);
    expect(keystore).to.deep.equal({
      default: b1,
      secret2: b2
    });
  });

  it("only extracts a single default secret", async function() {
    const b1 = Buffer.from("secret1");
    const b2 = Buffer.from("secret2");
    const s1 = b1.toString("base64");
    const s2 = b2.toString("base64");
    const keystore = await fromString(`${s1} ${s2}`);
    expect(keystore).to.deep.equal({
      default: b2
    });
  });
});

describe("fromEnv", function() {
  stubEnv();

  it("returns blank when AUTH_SECRET is not set", async function() {
    delete process.env.AUTH_SECRET;
    const keystore = await fromEnv();
    expect(keystore).to.deep.equal({});
  });

  it("processes AUTH_SECRET according to fromString", async function() {
    const b1 = Buffer.from("secret1");
    const b2 = Buffer.from("secret2");
    const s1 = b1.toString("base64");
    const s2 = b2.toString("base64");
    process.env.AUTH_SECRET = `${s1} secret2:${s2}`;
    const keystore = await fromEnv();
    expect(keystore).to.deep.equal({
      default: b1,
      secret2: b2
    });
  });
});

describe("fromConsul", function() {
  stubEnv();

  beforeEach(async function() {
    await consul.delAll();
  });

  it("extracts secrets", async function() {
    const b1 = Buffer.from("secret1");
    const b2 = Buffer.from("secret2");
    const s1 = b1.toString("base64");
    const s2 = b2.toString("base64");

    await consul.set("secret1", s1);
    await consul.set("secret2", s2);

    const keystore = await fromConsul();
    expect(keystore).to.deep.equal({
      secret1: b1,
      secret2: b2
    });
  });

  it("returns blank when no secrets are found", async function() {
    const keystore = await fromConsul();
    expect(keystore).to.deep.equal({});
  });

  it("returns blank when CONSUL_JWT_SECRET_PREFIX is not set", async function() {
    const b1 = Buffer.from("secret1");
    const s1 = b1.toString("base64");

    await consul.set("secret1", s1);

    delete process.env.CONSUL_JWT_SECRET_PREFIX;
    const keystore = await fromConsul();
    expect(keystore).to.deep.equal({});
  });
});

describe("fromMany", function() {
  it("reads from multiple builders", async function() {
    const builder1 = () => {
      return { a: 1 };
    };
    const builder2 = () => {
      return { b: 2 };
    };
    const keystore = await fromMany([builder1, builder2]);
    expect(keystore).to.deep.equal({
      a: 1,
      b: 2
    });
  });

  it("earlier builders take precedence", async function() {
    const builder1 = () => {
      return { a: 1 };
    };
    const builder2 = () => {
      return { a: 2 };
    };
    const keystore = await fromMany([builder1, builder2]);
    expect(keystore).to.deep.equal({
      a: 1
    });
  });
});

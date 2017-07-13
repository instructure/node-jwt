const consul = require("../consulKVStore")
const mapValues = require("lodash.mapvalues")

module.exports = async function buildKeystoreFromConsul() {
  if (process.env.CONSUL_JWT_SECRET_PREFIX) {
    const pairs = await consul.getAll()
    // flattens from [{a:1}, undefined, {b:2}] to {a:1, b:2}
    const keystore = Object.assign({}, ...pairs)
    return mapValues(keystore, val => Buffer.from(val, "base64"))
  }
  return {}
}

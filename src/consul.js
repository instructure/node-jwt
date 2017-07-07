const consul = require("consul")
const { promisify } = require("util")

const client = consul({
  host: process.env.CONSUL_HOST,
  port: process.env.CONSUL_PORT,
})

exports.getSigningSecrets = async function getSigningSecrets() {
  const keys = await exports.fetchKeys()
  const secrets = keys.map(key => {
    const kid = key.Key.replace(`${process.env.CONSUL_JWT_SECRET_PREFIX}/`, "")
    return { [kid]: key.Value }
  })
  return secrets
}

exports.fetchKeys = async function fetchKeys() {
  const options = {
    key: process.env.CONSUL_JWT_SECRET_PREFIX,
    datacenter: process.env.CONSUL_CANVAS_DATACENTER,
    recurse: true,
  }
  const get = promisify(client.kv.get).bind(client.kv)
  return await get(options)
}

exports.bootstrap = async function bootstrap() {
  function setOptions(n) {
    const k = n === 0 ? "default" : `test${n}`
    return {
      key: `${process.env.CONSUL_JWT_SECRET_PREFIX}/${k}`,
      value: `this-is-secret-${n}`,
      datacenter: process.env.CONSUL_CANVAS_DATACENTER,
    }
  }
  const set = promisify(client.kv.set).bind(client.kv)
  await set(setOptions(0))
  await set(setOptions(2))
}

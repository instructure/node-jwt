const consul = require("consul")
const { promisify } = require("util")

const client = consul({
  host: process.env.CONSUL_HOST,
  port: process.env.CONSUL_PORT,
})

const rawDel = promisify(client.kv.del).bind(client.kv)
const rawSet = promisify(client.kv.set).bind(client.kv)
const rawGet = promisify(client.kv.get).bind(client.kv)

exports.delAll = async function delAll(
  { prefix } = {
    prefix: process.env.CONSUL_JWT_SECRET_PREFIX,
  }
) {
  const options = {
    key: prefix,
    recurse: true,
  }
  return await rawDel(options)
}

exports.set = async function set(
  k,
  v,
  { prefix } = {
    prefix: process.env.CONSUL_JWT_SECRET_PREFIX,
  }
) {
  const options = {
    key: `${prefix}/${k}`,
    value: v,
  }
  return await rawSet(options)
}

exports.getAll = async function getAll(
  { prefix } = {
    prefix: process.env.CONSUL_JWT_SECRET_PREFIX,
  }
) {
  const options = {
    key: prefix,
    recurse: true,
  }
  const pairs = (await rawGet(options)) || []
  return pairs.map(kv => {
    const key = kv.Key.replace(`${prefix}/`, "")
    return { [key]: kv.Value }
  })
}

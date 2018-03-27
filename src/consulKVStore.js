const consul = require("consul");
const { promisify } = require("util");

const client = consul({
  host: process.env.CONSUL_HOST,
  port: process.env.CONSUL_PORT
});

const rawDel = promisify(client.kv.del).bind(client.kv);
const rawSet = promisify(client.kv.set).bind(client.kv);
const rawGet = promisify(client.kv.get).bind(client.kv);

exports.delAll = async function delAll(options) {
  const { prefix } = Object.assign(
    { prefix: process.env.CONSUL_JWT_SECRET_PREFIX },
    options
  );

  const consulOptions = {
    key: prefix,
    recurse: true
  };
  return await rawDel(consulOptions);
};

exports.set = async function set(k, v, options) {
  const { prefix } = Object.assign(
    { prefix: process.env.CONSUL_JWT_SECRET_PREFIX },
    options
  );

  const consulOptions = {
    key: `${prefix}/${k}`,
    value: v
  };
  return await rawSet(consulOptions);
};

exports.getAll = async function getAll(options) {
  const { prefix } = Object.assign(
    { prefix: process.env.CONSUL_JWT_SECRET_PREFIX },
    options
  );

  const consulOptions = {
    key: prefix,
    recurse: true
  };
  const pairs = (await rawGet(consulOptions)) || [];
  return pairs.map(kv => {
    const key = kv.Key.replace(`${prefix}/`, "");
    return { [key]: kv.Value };
  });
};

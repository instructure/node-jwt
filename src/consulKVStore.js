const consul = require("consul");
const { promisify } = require("util");

const client = consul({
  host: process.env.CONSUL_HOST,
  port: process.env.CONSUL_PORT
});

const rawDel = promisify(client.kv.del).bind(client.kv);
const rawSet = promisify(client.kv.set).bind(client.kv);
const rawGet = promisify(client.kv.get).bind(client.kv);

const CACHE_DURATION = 10 * 60 * 1000; // ten minutes
const cache = {
  result: undefined,
  validUntil: undefined,

  store(result) {
    const now = new Date();
    const nowMS = now.getTime();
    this.result = result;
    this.validUntil = nowMS + CACHE_DURATION;
  },

  isExpired() {
    const now = new Date();
    const nowMS = now.getTime();
    return !this.validUntil || this.validUntil < nowMS;
  },

  clear() {
    this.result = undefined;
    this.validUntil = undefined;
  },

  read() {
    return this.result;
  }
};

exports.delAll = async function delAll(options) {
  const { prefix } = Object.assign(
    { prefix: process.env.CONSUL_JWT_SECRET_PREFIX },
    options
  );

  const consulOptions = {
    key: prefix,
    recurse: true
  };
  const result = await rawDel(consulOptions);
  cache.clear();
  return result;
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
  const result = await rawSet(consulOptions);
  cache.clear();
  return result;
};

exports.getAllUncached = async function getAllUncached(options) {
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

exports.getAll = async function getAll(options) {
  if (options && options.prefix) {
    // don't cache explicit prefixes
    return await exports.getAllUncached(options);
  } else {
    if (cache.isExpired()) {
      cache.store(await exports.getAllUncached(options));
    }
    return cache.read();
  }
};

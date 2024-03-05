const Consul = require("consul");

const client = new Consul({
  host: process.env.CONSUL_HOST,
  port: process.env.CONSUL_PORT
});

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
  const consulOptions = {
    key: process.env.CONSUL_JWT_SECRET_PREFIX,
    recurse: true
  };
  const result = await client.kv.del(consulOptions.key);
  cache.clear();
  return result;
};

exports.set = async function set(k, v, options) {
  const consulOptions = {
    key: `${process.env.CONSUL_JWT_SECRET_PREFIX}/${k}`,
    value: v
  };
  const result = await client.kv.set(consulOptions);
  cache.clear();
  return result;
};

exports.getAllUncached = async function getAllUncached(options) {
  const consulOptions = {
    key: process.env.CONSUL_JWT_SECRET_PREFIX,
    recurse: true
  };
  const pairs = (await client.kv.get(consulOptions)) || [];
  return pairs.map(kv => {
    const key = kv.Key.replace(`${process.env.CONSUL_JWT_SECRET_PREFIX}/`, "");
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

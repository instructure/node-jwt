const consul = require("../consulKVStore");

const mapObj = (obj, fn) => {
  const mapped = Object.assign({}, obj);
  Object.keys(obj).forEach(key => {
    /* eslint-disable */
    // it would cry about users injecting functions, but 
    // this is a static function anyway
    mapped[key] = fn(obj[key]);
    /* eslint-enable */
  });
  return mapped;
};

module.exports = async function buildKeystoreFromConsul() {
  if (process.env.CONSUL_JWT_SECRET_PREFIX) {
    const pairs = await consul.getAll();
    // flattens from [{a:1}, undefined, {b:2}] to {a:1, b:2}
    const keystore = Object.assign({}, ...pairs);

    const vals = mapObj(keystore, key => {
      return Buffer.from(key, "base64");
    });
    return vals;
  }
  return {};
};

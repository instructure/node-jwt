module.exports = async function buildKeystoreFromString(source) {
  if (source === "") {
    return {};
  }
  const keys = source.split(/\s+/);
  const keystore = keys.map(key => {
    const parts = key.split(":");
    if (parts.length === 1) {
      const [value] = parts;
      return { default: Buffer.from(value, "base64") };
    } else if (parts.length === 2) {
      const [kid, value] = parts;
      return { [kid]: Buffer.from(value, "base64") };
    } else {
      return undefined;
    }
  });
  // flattens from [{a:1}, undefined, {b:2}] to {a:1, b:2}
  return Object.assign({}, ...keystore);
};

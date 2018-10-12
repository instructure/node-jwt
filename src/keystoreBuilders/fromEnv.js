const fromString = require("./fromString");

module.exports = async function buildKeystoreFromEnvironment() {
  if (process.env.AUTH_SECRET) {
    return fromString(process.env.AUTH_SECRET);
  }
  return {};
};

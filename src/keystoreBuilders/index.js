const fromEnv = require("./fromEnv");
const fromConsul = require("./fromConsul");

exports.fromEnv = fromEnv;
exports.fromConsul = fromConsul;

exports.fromMany = async function fromMany(builders = [fromEnv, fromConsul]) {
  // fromMany([highestPriority, ..., lowestPriority])

  builders.reverse();
  const results = await Promise.all(builders.map(f => f()));
  return Object.assign({}, ...results);
};

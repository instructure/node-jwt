const chai = require("chai");
chai.use(require("sinon-chai"));

chai.expectRejection = async function expectRejection(promise) {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  return chai.expect.fail(
    promise,
    null,
    "Expected promise to be rejected but it was fulfilled"
  );
};

module.exports = chai;

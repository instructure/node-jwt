const util = require("util");

function UnauthorizedError(...args) {
  let error, message;
  if (args.length > 1) {
    [error, message] = args;
  } else {
    [message] = args;
  }

  this.name = this.constructor.name;
  this.message = message;
  if (error && error.message) {
    this.JWTError = error.message;
  }
  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
}
util.inherits(UnauthorizedError, Error);

module.exports = UnauthorizedError;

// lets us play with process.env.* for those functions the use them, without
// bleeding those modifications outside the scope of the specific tests
module.exports = function stubEnv() {
  let oldEnv
  beforeEach(() => {
    oldEnv = process.env
    process.env = Object.assign({}, process.env)
  })
  afterEach(() => {
    process.env = oldEnv
  })
}

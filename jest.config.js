/** @type {import('ts-jest').JestConfigWithTsJest} **/
module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.(ts|tsx|js|jsx)$": "babel-jest",
  },
  // Configure transformIgnorePatterns to process ES modules in node_modules
  transformIgnorePatterns: [
    "node_modules/(?!(@noble/secp256k1))"
  ],
};
module.exports = {
    parser: '@typescript-eslint/parser', // Specifies the ESLint parser
    parserOptions: {
      ecmaVersion: 2020, // Allows for modern ECMAScript features
      sourceType: 'module', // Allows for the use of imports
    },
    plugins: ['@typescript-eslint'],
    extends: [
      'eslint:recommended',
      'plugin:@typescript-eslint/recommended', // Uses recommended rules from the @typescript-eslint/eslint-plugin
    ],
    rules: {
      // Customize rules as needed
    },
  };
  
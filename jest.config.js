export default {
  moduleNameMapper: {
    '^(\\..*)\\.jsx?$': '$1', // support for ts imports with .js extensions
  },
  modulePathIgnorePatterns: ['<rootDir>/dist', '<rootDir>/tmp'],
  testMatch: ['<rootDir>/__tests__/**/*.test.ts'],
  extensionsToTreatAsEsm: ['.ts', '.tsx', '.mts', '.mtsx'],
  injectGlobals: false,
};

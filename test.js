exports = module.exports = {
    justencrypt: require('./'), // for debugging purposes
    keyderivation: require('./test/keyderivation.test'),
    keyderivation_async: require('./test/keyderivation_async.test'),
    encryption: require('./test/encryption.test'),
    mnemonic: require('./test/mnemonic.test')
};

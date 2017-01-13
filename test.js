exports = module.exports = {
    justencrypt: require('./'),
    keyderivation: require('./test/keyderivation.test'),
    keyderivation_async: require('./test/keyderivation_async.test'),
    encryption: require('./test/encryption.test'),
    encryption_async: require('./test/encryption_async.test'),
    mnemonic: require('./test/mnemonic.test')
};

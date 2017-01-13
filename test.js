exports = module.exports = {
    justencrypt: require('./'), // for debugging purposes
    keyderivation: require('./test/keyderivation.test'),
    keyderivation_async: require('./test/keyderivation_async.test'),
    encryption: require('./test/encryption.test'),
    mnemonic: require('./test/mnemonic.test'),
    pbkdf2Sha512: require('./test/pbkdf2_sha512.test')
};

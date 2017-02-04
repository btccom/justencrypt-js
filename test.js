exports = module.exports = {
    // for debugging purposes
    justencrypt: require('./'),

    // test config which we can modify from external source
    config: require('./test/testconfig'),

    // for reading config values from querystring
    qs: require('querystring'),

    keyderivation: require('./test/keyderivation.test'),
    encryption: require('./test/encryption.test'),
    pbkdf2Sha512: require('./test/pbkdf2_sha512.test')
};

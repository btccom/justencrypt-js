module.exports = {
    Buffer: Buffer,

    KeyDerivation: require('./lib/keyderivation'),
    Encryption: require('./lib/encryption'),
    webCryptoPbkdf2: require('./lib/pbkdf2_sha512-webcrypto')
};

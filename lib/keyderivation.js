var assert = require('assert');

var pbkdf2Sha512 = require('./pbkdf2_sha512');
var pbkdf2Sha512WebCrypto = require('./pbkdf2_sha512-webcrypto');
var webworkifier = require('./webworkifier');

var KeyDerivation = {
    defaultIterations: 35000,
    subkeyIterations: 1,
    keySizeBits: 256,

    useWebWorker: true,
    useWebCrypto: true
};

KeyDerivation.compute = function(pw, salt, iterations) {
    iterations = iterations || KeyDerivation.defaultIterations;
    assert(pw instanceof Buffer, 'Password must be provided as a Buffer');
    assert(salt instanceof Buffer, 'Salt must be provided as a Buffer');
    assert(salt.length > 0, 'Salt must not be empty');
    assert(typeof iterations === 'number', 'Iterations must be a number');
    assert(iterations > 0, 'Iteration count should be at least 1');

    if (salt.length > 0x80) {
        throw new Error('Sanity check: Invalid salt, length can never be greater than 128');
    }

    var keySizeBytes = KeyDerivation.keySizeBits / 8;

    return pbkdf2Sha512WebCrypto.isSupported()
        .then(function(isSupported) {
            if (KeyDerivation.useWebCrypto && isSupported) {
                return pbkdf2Sha512WebCrypto.digest(pw, salt, iterations, keySizeBytes);
            } else if (KeyDerivation.useWebWorker && webworkifier.isSupported()) {
                return webworkifier({
                    method: 'pbkdf2Sha512.digest',
                    pw: typeof pw !== "undefined" ? Buffer.from(pw) : undefined, // Buffer.from will ensure that we transfer to webworker without issues
                    salt: typeof salt !== "undefined" ? Buffer.from(salt) : undefined, // --^
                    iterations: iterations,
                    keySizeBytes: keySizeBytes
                }).then(function(result) {
                    return Buffer.from(result);
                });
            } else {
                return pbkdf2Sha512.digest(pw, salt, iterations, keySizeBytes);
            }
        });
};

module.exports = KeyDerivation;

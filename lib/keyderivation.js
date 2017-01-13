var assert = require('assert');
var q = require('q');

var pbkdf2Sha512 = require('./pbkdf2_sha512');
var pbkdf2Sha512WebCrypto = require('./pbkdf2_sha512-webcrypto');

var KeyDerivation = {
    defaultIterations: 35000,
    subkeyIterations: 1,
    keySizeBits: 256
};

KeyDerivation.normalize = function(pw, salt, iterations) {
    iterations = iterations || KeyDerivation.defaultIterations;
    assert(pw instanceof Buffer, 'Password must be provided as a Buffer');
    assert(salt instanceof Buffer, 'Salt must be provided as a Buffer');
    assert(salt.length > 0, 'Salt must not be empty');
    assert(typeof iterations === 'number', 'Iterations must be a number');
    assert(iterations > 0, 'Iteration count should be at least 1');

    if (salt.length > 0x80) {
        throw new Error('Sanity check: Invalid salt, length can never be greater than 128');
    }

    return [pw, salt, iterations];
};

KeyDerivation.computeSync = function(pw, salt, iterations) {
    var r = KeyDerivation.normalize(pw, salt, iterations);
    pw = r[0];
    salt = r[1];
    iterations = r[2];

    return pbkdf2Sha512.digest(pw, salt, iterations, KeyDerivation.keySizeBits / 8);
};

KeyDerivation.computeAsync = function(pw, salt, iterations) {
    return q.when()
        .then(function() {
            var r = KeyDerivation.normalize(pw, salt, iterations);
            pw = r[0];
            salt = r[1];
            iterations = r[2];

            return pbkdf2Sha512WebCrypto.isSupported()
                .then(function(isSupported) {
                    console.log('isSupported', isSupported);

                    if (isSupported) {
                        return pbkdf2Sha512WebCrypto.digest(pw, salt, iterations, KeyDerivation.keySizeBits / 8);
                    } else {
                        return pbkdf2Sha512.digest(pw, salt, iterations, KeyDerivation.keySizeBits / 8);
                    }
                });
        });
};

module.exports = KeyDerivation;

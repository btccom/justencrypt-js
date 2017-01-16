var q = require('q');

var KeyDerivation = require('./keyderivation');
var pbkdf2Sha512WebCrypto = require('./pbkdf2_sha512-webcrypto');

var KeyDerivationAsync = {
    useWebWorker: require('./use-webworker')()
};

KeyDerivationAsync.compute = function(pw, salt, iterations) {
    return pbkdf2Sha512WebCrypto.isSupported()
        .then(function(isSupported) {
            if (!isSupported && KeyDerivationAsync.useWebWorker) {
                return require('./webworkifier')({
                    method: 'KeyDerivation.computeAsync',
                    pw: typeof pw !== "undefined" ? Buffer.from(pw) : undefined, // Buffer.from will ensure that we transfer to webworker without issues
                    salt: typeof salt !== "undefined" ? Buffer.from(salt) : undefined, // --^
                    iterations: iterations
                }).then(function (result) {
                    return Buffer.from(result);
                });
            } else {
                return q.when()
                    .then(function () {
                        return KeyDerivation.computeSync(pw, salt, iterations);
                    });
            }
        });
};

module.exports = KeyDerivationAsync;

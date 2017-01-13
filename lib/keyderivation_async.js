var q = require('q');

var KeyDerivation = require('./keyderivation');

var KeyDerivationAsync = {
    useWebWorker: require('./use-webworker')()
};

KeyDerivationAsync.compute = function(pw, salt, iterations) {
    if (KeyDerivationAsync.useWebWorker) {
        return require('./webworkifier')({
            method: 'KeyDerivation.computeSync',
            pw: pw,
            salt: salt,
            iterations: iterations
        }).then(function(result) {
            return Buffer.from(result);
        });
    } else {
        return q.when()
            .then(function() {
                return KeyDerivation.computeSync(pw, salt, iterations);
            });
    }
};

module.exports = KeyDerivationAsync;

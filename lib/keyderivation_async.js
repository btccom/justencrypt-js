var q = require('q');

var KeyDerivation = require('./keyderivation');
var webworkifier = require('./webworkifier');

var KeyDerivationAsync = {
    useWebWorker: require('./use-webworker')(),
    webworker: {}
};

KeyDerivationAsync.compute = function(pw, salt, iterations) {
    if (KeyDerivationAsync.useWebWorker) {
        return q.when()
            .then(function() {
                return webworkifier.workify(KeyDerivationAsync.webworker, {
                    method: 'KeyDerivation.computeSync',
                    pw: pw,
                    salt: salt,
                    iterations: iterations
                });
            });
    } else {
        return q.when()
            .then(function() {
                return KeyDerivation.computeSync(pw, salt, iterations);
            });
    }
};

module.exports = KeyDerivationAsync;

var q = require('q');

var KeyDerivation = require('./keyderivation');

var KeyDerivationAsync = {};

KeyDerivationAsync.compute = function(pw, salt, iterations) {
    return q.when()
        .then(function() {
            return KeyDerivation.computeSync(pw, salt, iterations);
        });
};

module.exports = KeyDerivationAsync;

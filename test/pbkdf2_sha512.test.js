var assert = require('assert');
var _ = require('lodash');
var q = require('q');

var vectors = require('./vectors');
var justencrypt = require('../');

var isNodeJS = !process.browser;
var isWeb = !isNodeJS;

var modules = [
    {name: 'pbkdf2_sha512',           web: true, node: true, async: false, digest: require('../lib/pbkdf2_sha512').digest},
    {name: 'pbkdf2_sha512-asm',       web: true, node: false, async: false, digest: require('../lib/pbkdf2_sha512-asm').digest},
    {name: 'pbkdf2_sha512-webcrypto', web: true, node: false, async: true, digest: require('../lib/pbkdf2_sha512-webcrypto').digest}
];

_.forEach(modules, function(module) {
    if (isNodeJS && !module.node || isWeb && !module.web) {
        return;
    }

    describe(module.name, function () {
        _.forEach(vectors.keyderivation, function (vector, key) {
            it('vector ' + key + ' produces the right key', function () {
                var password = new Buffer(vector.password, 'hex');
                var salt = new Buffer(vector.salt, 'hex');
                var iterations = vector.iterations;

                if (module.async) {
                    return module.digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8)
                        .then(function (output) {
                            console.log(output);
                            assert.equal(output.toString('hex'), vector.output);
                        });
                } else {
                    var output = module.digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8);
                    assert.equal(output.toString('hex'), vector.output);
                }
            });
        });
    });
});

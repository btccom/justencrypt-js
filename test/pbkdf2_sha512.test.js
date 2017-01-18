var assert = require('assert');
var _ = require('lodash');
var q = require('q');

var vectors = require('./vectors');
var justencrypt = require('../');

var isNodeJS = !process.browser;
var isWeb = !isNodeJS;

var modules = [
    {name: 'pbkdf2_sha512',           web: true, node: true, async: false, module: require('../lib/pbkdf2_sha512')},
    {name: 'pbkdf2_sha512-asm',       web: true, node: false, async: false, module: require('../lib/pbkdf2_sha512-asm')},
    {name: 'pbkdf2_sha512-webcrypto', web: true, node: false, async: true, module: require('../lib/pbkdf2_sha512-webcrypto')}
];

_.forEach(modules, function(module) {
    if (isNodeJS && !module.node || isWeb && !module.web) {
        return;
    }

    describe(module.name, function() {
        var digest = module.module.digest;

        // if it has an isSupported function, check if it's working properly
        if (typeof module.module.isSupported !== "undefined") {
            it('should be supported', function() {
                // async module should have async isSupported
                if (module.async) {
                    return module.module.isSupported()
                        .then(function(isSupported) {
                            assert.ok(isSupported);
                        });
                } else {
                    assert.ok(module.module.isSupported);
                }
            });
        }

        _.forEach(vectors.keyderivation, function(vector, key) {
            it('vector ' + key + ' produces the right key', function() {
                var password = new Buffer(vector.password, 'hex');
                var salt = new Buffer(vector.salt, 'hex');
                var iterations = vector.iterations;

                if (module.async) {
                    return digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8)
                        .then(function(output) {
                            assert.equal(output.toString('hex'), vector.output);
                        });
                } else {
                    var output = digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8);
                    assert.equal(output.toString('hex'), vector.output);
                }
            });
        });
    });

    describe(module.name + " benchmark", function() {
        var n = 10; // n loops
        var iterations = 35000;
        var digest = module.module.digest;
        var password = new Buffer("ff", 'hex');
        var salt = new Buffer("ff", 'hex');

        it('first with ' + iterations + ' iterations', function() {
            var start = new Date;

            return q.when().then(function() {
                return digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8);
            }).then(function() {
                var time = new Date - start;

                console.log(module.name + ' ' + time + 'ms/first');
            });
        });

        it('benchmark ' + n + ' loops with ' + iterations + ' iterations', function() {
            var start = new Date;

            return q.all(_.repeat("1", n).split("").map(function() {
                return digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8);
            })).then(function() {
                var time = new Date - start;

                console.log(module.name + ' ' + (time / n) + 'ms/loop');
            });
        });
    });
});

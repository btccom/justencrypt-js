var assert = require('assert');
var _ = require('lodash');
var q = require('q');

var justencrypt = require('../');
var vectors = require('./vectors');
var testconfig = require('./testconfig');

var isNodeJS = !process.browser;
var isWeb = !isNodeJS;

var modules = [
    {name: 'pbkdf2_sha512',           web: true, node: true, async: false, module: require('../lib/pbkdf2_sha512')},
    {name: 'pbkdf2_sha512-asm',       web: true, node: false, async: false, module: require('../lib/pbkdf2_sha512-asm')},
    {name: 'pbkdf2_sha512-webcrypto', web: true, node: false, async: true, module: require('../lib/pbkdf2_sha512-webcrypto'), requires_config: ['webcrypto']}
];

_.forEach(modules, function(module) {
    // don't test modules on platforms that don't support them at all
    if (isNodeJS && !module.node || isWeb && !module.web) {
        return;
    }

    describe(module.name, function() {
        var digest = module.module.digest;
        var shouldBeSupported = true;

        before(function() {
            if (module.requires_config) {
                _.forEach(module.requires_config, function(c) {
                    shouldBeSupported = shouldBeSupported && !!testconfig[c];
                });
            }
        });

        describe("test", function() {
            it.skip('check isSupported', function() {
                if (typeof module.module.isSupported === "undefined") {
                    this.skip("module does not have isSupported");
                }

                // async module should have async isSupported
                if (module.async) {
                    return module.module.isSupported()
                        .then(function(isSupported) {
                            assert.equal(isSupported, shouldBeSupported, shouldBeSupported ? "should be supported" : "shouldn't be supported");
                        });
                } else {
                    assert.equal(module.module.isSupported, shouldBeSupported, shouldBeSupported ? "should be supported" : "shouldn't be supported");
                }
            });

            _.forEach(vectors.keyderivation, function(vector, key) {
                it('vector ' + key + ' produces the right key', function() {
                    if (!shouldBeSupported) {
                        this.skip("not supported");
                    }

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

        describe("benchmark", function() {
            var n = 10; // n loops
            var iterations = 35000;
            var digest = module.module.digest;
            var password = new Buffer("ff", 'hex');
            var salt = new Buffer("ff", 'hex');

            it('first with ' + iterations + ' iterations', function() {
                if (!shouldBeSupported) {
                    this.skip("not supported");
                }

                var start = new Date();

                return q.when().then(function() {
                    return digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8);
                }).then(function() {
                    var time = (new Date()) - start;

                    console.log(module.name + ' ' + time + 'ms/first');
                });
            });

            it('benchmark ' + n + ' loops with ' + iterations + ' iterations', function() {
                if (!shouldBeSupported) {
                    this.skip("not supported");
                }

                var start = new Date();

                return q.all(_.repeat("1", n).split("").map(function() {
                    return digest(password, salt, iterations, justencrypt.KeyDerivation.keySizeBits / 8);
                })).then(function() {
                    var time = (new Date()) - start;

                    console.log(module.name + ' ' + (time / n) + 'ms/loop');
                });
            });
        });
    });
});

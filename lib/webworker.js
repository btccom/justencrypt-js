var KeyDerivation = require('./keyderivation');

module.exports = function(self) {
    self.addEventListener('message', function(e) {
        var data = e.data || {};

        switch (data.method) {
            case 'KeyDerivation.computeAsync':
                (function() {
                    try {
                        var pw = typeof data.pw !== "undefined" ? Buffer.from(data.pw.buffer) : undefined;
                        var salt = typeof data.salt !== "undefined" ? Buffer.from(data.salt.buffer) : undefined;
                        var iterations = typeof data.iterations !== "undefined" ? data.iterations : undefined;

                        KeyDerivation.computeAsync(pw, salt, iterations)
                            .then(function(result) {
                                self.postMessage({id: data.id, result: result});
                            }, function(err) {
                                throw err; // @TODO: this won't work properly
                            });
                    } catch (e) {
                        e.id = data.id;
                        throw e;
                    }
                })();
                break;

            default:
                e = new Error('Invalid method [' + e.method + ']');
                e.id = data.id;
                throw e;
        }
    }, false);
};

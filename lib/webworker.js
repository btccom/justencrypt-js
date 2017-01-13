var KeyDerivation = require('./keyderivation');

module.exports = function(self) {
    self.addEventListener('message', function(e) {
        var data = e.data || {};

        switch (data.method) {
            case 'KeyDerivation.computeSync':
                (function() {
                    try {
                        var pw = typeof data.pw !== "undefined" ? Buffer.from(data.pw.buffer) : undefined;
                        var salt = typeof data.salt !== "undefined" ? Buffer.from(data.salt.buffer) : undefined;
                        var iterations = typeof data.iterations !== "undefined" ? data.iterations : undefined;

                        var result = KeyDerivation.computeSync(pw, salt, iterations);

                        self.postMessage({id: data.id, result: result});
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

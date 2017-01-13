var Encryption = require('./encryption');
var KeyDerivation = require('./keyderivation');

module.exports = function(self) {
    console.log('webworker::init');

    self.addEventListener('message', function(e) {
        var data = e.data || {};

        switch (data.method) {
            case 'Encryption.encryptWithSaltAndIV':
                (function() {
                    try {
                        var pt = typeof data.pt !== "undefined" ? Buffer.from(data.pt.buffer) : undefined;
                        var pw = typeof data.pw !== "undefined" ? Buffer.from(data.pw.buffer) : undefined;
                        var saltBuf = typeof data.saltBuf !== "undefined" ? Buffer.from(data.saltBuf.buffer) : undefined;
                        var iv = typeof data.iv !== "undefined" ? Buffer.from(data.iv.buffer) : undefined;
                        var iterations = typeof data.iterations !== "undefined" ? data.iterations : undefined;

                        var result = Encryption.encryptWithSaltAndIVSync(pt,  pw, saltBuf, iv, iterations);

                        self.postMessage({id: data.id, result: result});
                    } catch (e) {
                        e.id = data.id;
                        throw e;
                    }
                })();
            break;

            case 'Encryption.decrypt':
                (function() {
                    try {
                        var ct = typeof data.ct !== "undefined" ? Buffer.from(data.ct.buffer) : undefined;
                        var pw = typeof data.pw !== "undefined" ? Buffer.from(data.pw.buffer) : undefined;

                        var result = Encryption.decryptSync(ct,  pw);

                        self.postMessage({id: data.id, result: result});
                    } catch (e) {
                        e.id = data.id;
                        throw e;
                    }
                })();
                break;

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

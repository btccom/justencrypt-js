/* global URL */
var q = require('q');
var webworkify = require('webworkify');

var worker = webworkify(require('./webworker'));
var first = true;
var lastId = 0;

var executeFunction = function(self, message) {
    // create promise for result
    var deferred = q.defer();

    try {
        // keep a unique id to distinguish between responses
        var id = lastId++;

        var onMessage = function(e) {
            // on first message we cleanup memory by revoking the blob
            if (first) {
                first = false;
                URL.revokeObjectURL(worker.objectURL);
            }

            // don't process messages that aren't for us
            if (e.data.id !== id) {
                return;
            }

            deferred.resolve(e.data.result);
        };

        var onError = function(e) {
            deferred.reject(new Error(e.message.replace(/Uncaught (Assertion)?Error: /, '')));
        };

        var unsub = function() {
            worker.removeEventListener("message", onMessage);
            worker.removeEventListener("error", onError);
        };

        // register event listeners
        worker.addEventListener('message', onMessage, false);
        worker.addEventListener('error', onError, false);

        // submit message to worker to init work
        message.id = id;
        worker.postMessage(message);

        // return promise
        return deferred.promise.then(function(r) {
            unsub();
            return r;
        }, function(e) {
            unsub();
            throw e;
        });
    } catch (e) {
        deferred.reject(e);
        return deferred.promise;
    }
};

module.exports = function(message) {
    return executeFunction(worker, message);
};

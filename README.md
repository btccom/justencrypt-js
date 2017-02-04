JustEncrypt
===========

[![Latest Stable Version](https://badge.fury.io/js/justencrypt.svg)](https://www.npmjs.org/package/justencrypt)
[![Build Status](https://travis-ci.org/btccom/justencrypt-js.png?branch=master)](https://travis-ci.org/btccom/justencrypt-js)
[![Sauce Test Status](https://saucelabs.com/buildstatus/justencrypt-js)](https://saucelabs.com/u/justencrypt-js)

[![Sauce Test Status](https://saucelabs.com/browser-matrix/justencrypt-js.svg)](https://saucelabs.com/u/justencrypt-js)

This package is being tested against the following NodeJS versions;
   - 0.11
   - 0.12
   - 5.11
   - 6.3.0
   - 7.1.0

Usage
-----
All functions return promises to make it easy to automatically use webworkers or WebCrypto API in browsers that support it!

#### KeyDerivation
```js
// iterations is optional and defaults to 35k iterations
justencrypt.KeyDerivation.compute(new Buffer(rawPassword, 'utf8'), saltBuffer, iterations)
    .then(function(keyBuffer) {
        console.log(keyBuffer.toString('base64'));
    });
```

#### Encryption
The result of `encrypt` is encoded as `iter || saltLen8 || salt || iv || tag || ct`,  
when this is fed into `decrypt` it will be able decode the salt and iterations used.

```js
// iterations is optional and defaults to 35k iterations
justencrypt.Encryption.encrypt(new Buffer(rawPassword, 'utf8'), dataBuffer, iterations)
    .then(function(encryptedBuffer) {
        console.log(encryptedBuffer.toString('base64'));
    });

justencrypt.Encryption.decrypt(encryptedBuffer, new Buffer(rawPassword, 'utf8'))
    .then(function(decryptedDataBuffer) {
        console.log(decryptedDataBuffer.toString('base64'));
    });
```

#### EncryptionMnemonic
To make the result of `encrypt` human readable (so it is easier to write down) it's possible to encode it as an mnemonic.  
Use the `justencrypt-mnemonic` package for this!

#### Choosing iterations
The default iterations is `justencrypt.KeyDerivation.defaultIterations` and is set to **35000**, 
this is a number that should remain secure enough for a while when using a password.  
If you don't pass in the `iterations` argument it will default to this.

If you're encrypting with a random byte string used as password then you can use the same code,
except in that case setting the iterations to 1 is secure as there's no need to stretch the password.  
You can use `justencrypt.KeyDerivation.subkeyIterations` in that case to make it clear what your intentions are.

Development / Contributing
--------------------------
You should have `mocha`, `istanbul` and `grunt-cli` installed globally, if not run `npm install -g mocha instanbul grunt-cli`.  
Also recommended to have `phantomjs >= 1.9.8` on `$PATH` to speed up the `asmcrypto.js` build; https//github.com/Medium/phantomjs/releases/download/v1.9.19/phantomjs-1.9.8-linux-x86_64.tar.bz2

Unit Tests are created with Mocha and can be ran with `npm test` (or `mocha`)

We also run jshint and jscs, these are automatically ran by [travis-ci](https://travis-ci.org/btccom/justencrypt) for every commit and pull request.

```bash
jshint main.js lib/ test/ && jscs main.js lib/ test/
```

or simply `npm run-script lint`

Uglify
------
If you're planning to uglify/minify the javascript yourself, make sure to exclude the following variable names from being mangled:  
`['Buffer', 'sha512_asm', 'asm']`

License
-------
JustEncrypt is released under the terms of the MIT license. See LICENCE.md for more information or see http://opensource.org/licenses/MIT.

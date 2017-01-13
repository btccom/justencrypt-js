JustEncrypt
===========
[![Latest Stable Version](https://badge.fury.io/js/justencrypt.svg)](https://www.npmjs.org/package/justencrypt)
[![Build Status](https://travis-ci.org/btccom/justencrypt.png?branch=master)](https://travis-ci.org/btccom/justencrypt)

This package is being tested against;  
 - NodeJS:
   - 0.11
   - 0.12
   - 5.11
   - 6.3.0
   - 7.1.0

Usage
-----
You can choose to either use the `*Sync` functions for non-async usage or use the normal functions which return promises.  
The functions that return promises will automatically use webworkers or WebCrypto API in browsers that support it, so they are recommended!

#### KeyDerivation
```
// iterations is optional and defaults to 35k iterations
var keyBuffer = justencrypt.KeyDerivation.computeSync(new Buffer(rawPassword, 'utf8'), saltBuffer, iterations);
```

#### Encryption
The result of `encrypt` / `encryptSync` is encoded as `iter || saltLen8 || salt || iv || tag || ct`,  
when this is fed into `decrypt` / `decryptSync` it will be able decode the salt and iterations used.

```
// iterations is optional and defaults to 35k iterations
var encryptedBuffer = justencrypt.Encryption.encryptSync(new Buffer(rawPassword, 'utf8'), dataBuffer, iterations);

var decryptedDataBuffer = justencrypt.Encryption.decryptSync(encryptedBuffer, new Buffer(rawPassword, 'utf8'));
```

#### EncryptionMnemonic
To make the result of `encrypt` / `encryptSync` human readable (so it is easier to write down) it's possible to encode it as an mnemonic.  
We're using the Bitcoin BIP39 way of encoding entropy to mnemonic, but ignoring the (weak) password protection BIP39 originally had.  
We also ensure the data is padded correctly.

**IMPORTANT:** This is only meant to be used to encode results of `encrypt` / `encryptSync`, don't use this for anything else!

```
var mnemonicString = justencrypt.EncryptionMnemonic.encode(encryptedBuffer);
var encryptedBuffer = justencrypt.EncryptionMnemonic.decode(mnemonicString);
```

Development / Contributing
--------------------------
You should have `mocha`, `istanbul` and `grunt-cli` installed globally, if not run `npm install -g mocha instanbul grunt-cli`.

Unit Tests are created with Mocha and can be ran with `npm test` (or `mocha`)

We also run jshint and jscs, these are automatically ran by [travis-ci](https://travis-ci.org/btccom/jusencrypt) for every commit and pull request.
```
jshint main.js lib/ test/ && jscs main.js lib/ test/
```
or simply `npm run-script lint`

Uglify
------
If you're planning to uglify/minify the javascript yourself, make sure to exclude the following variable names from being mangled:  
`['Buffer']`

License
-------
JustEncrypt is released under the terms of the MIT license. See LICENCE.md for more information or see http://opensource.org/licenses/MIT.

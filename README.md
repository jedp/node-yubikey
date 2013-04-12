A Node.js client library for verifying OTPs with the Yubikey api servers.

## Install

`npm install yubikey`

Or fork this repo and help improve it.

## Usage:

```javascript
var yubikey = new(require('yubikey'));

function onVerify(err) {
  // if err is null, you're good
}

yubikey.verify('vvvvvvcurikvhjcvnlnbecbkubjvuittbifhndhn', onVerify);
```

## Testing

Plug your YubiKey in, and run `./test.js`.  Try entering the same token twice.

## Resources

- [YubiKey Validation Protocol 2.0](http://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20)


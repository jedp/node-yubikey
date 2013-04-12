#!/usr/bin/env node

const
stdin = process.stdin,
stdout = process.stdout,
yubikey = new(require('./lib/yubikey'));

function verify(otp) {
  yubikey.verify(otp, function(err) {
    if (err) {
      stdout.write(err + "\n");
    } else {
      stdout.write("Success!  Your token was verified.\n");
    }
    process.exit(0);
  });
}

function readOTP() {
  stdin.resume();
  stdout.write("YubiKey OTP: ");
  stdin.once('data', function(buf) {
    verify(buf.toString().trim());
  });
}

if (!module.parent) {
  readOTP();
}


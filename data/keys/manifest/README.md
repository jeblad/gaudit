gAudit's public keys for the signed manifest, as minisign public key files
(`*.pub`). Every file here is built into the helper; keep two during a
change of keys. The secret key is kept offline and never in this repository.

Make a key pair with `minisign -G -p gaudit-manifest.pub -s <somewhere safe>`.

# Signing identity fixture

`test-signing-identity.p12.b64` is a self-signed, test-only PKCS#12 identity.
Its intentionally public password is `macho-test`. It provides deterministic
CMS integrity coverage and carries no production trust, Apple program
membership, or secret material.

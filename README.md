# AnonPGP

Local-only OpenPGP suite. Multiple keypairs, encrypt/decrypt, sign/verify, QR exchange.

This is the source for one of the [anonymous.gratis](https://anonymous.gratis/apps.html) Android apps.

- **Package**: `gratis.anon.pgp`
- **License**: GPL-3.0-or-later
- **Downloads**: https://anonymous.gratis/apps.html
- **F-Droid repo**: https://anonymous.gratis/fdroid/repo
- **Tip portal**: http://ieyezgeojxw73hv4szrkbreea3rd6ri7xfbevngi63uabothn226euyd.onion

## Build

Requires Android SDK + Java 17.

```
./gradlew assembleRelease
```

Signing is handled via a `signing.properties` file (gitignored) pointing to a keystore that lives off-VCS. Without it, `assembleRelease` still works and produces an unsigned APK at `app/build/outputs/apk/release/`.

## Security

If you find a vulnerability, please email <admin@anon.gratis> with [`PGP D1B6F514EB01BA1E5486740EE03B35EB06E1136F`](https://anonymous.gratis/pgp.txt).

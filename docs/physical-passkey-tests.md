# Physical-device interoperability runner

Physical presence/PIN/biometric prompts require the device holder. No virtual-authenticator success or metadata catalog
entry establishes a physical device test. No physical device has been exercised in this workspace.

The existing functional UI can be tested in an isolated stack using an interactive terminal:

```sh
python3 tests/backchannel_stack_test.py --mode physical \
  --device-model 'model, without serial number' \
  --device-firmware 'firmware version' \
  --device-platform 'OS and Chrome version'
```

Java 21 artifacts, local Compose PostgreSQL/Redis, Chrome and `.env` development inputs are required. The runner opens a
visible **new Chrome profile**, uses temporary database schemas/Redis namespace, and installs **no virtual
authenticator**. It refuses unattended/noninteractive execution. Device/platform labels are operator evidence only and
never authorize access. Existing attestation configuration is respected; explicitly configure REQUIRED and reviewed
signer/manufacturer roots/metadata when testing hardware attestation. Default NONE only tests ordinary passkey
interoperability.

Use employee and the private `.env` password; the runner never prints the password. Enroll through IAM, complete the
real device prompt, sign out and use passkey login. Open both client applications and protected APIs. Check existing MFA
if configured. Remove the key after current-password/MFA reauthentication, and confirm both applications lose access.
Press Enter in the terminal only after completing the flow. The runner records server enrollment/authentication/removal
counts plus supplied labels in a uniquely named `benchmarks/results/physical-*.json`, then cleans only its own
processes, Chrome profile and test schemas/namespace.

The JSON is a server-observation record, not certification or proof of every manual step. It does not automatically
verify device firmware identity, user experience, protected-API rendering, negative origin tests or every OS/browser
combination. Capture reviewed outcomes separately for cancel/retry, interrupted enrollment, device loss, origin/RP
rejection, unsupported UV/resident devices, metadata revocation and outage recovery. Never attach passwords, PINs,
recovery codes, raw assertions, credential IDs, device serial numbers or private keys to shared evidence.

Server credential removal does not erase a resident passkey from the physical authenticator or OS/cloud key store.
Remove the test credential there using device/vendor settings after the test. Avoid enrolling a production account.
Other browsers/phone ecosystems need their own operator review; the launcher does not certify Safari, Firefox, NFC,
Bluetooth or hybrid transport.

Run [automated virtual coverage](passkeys.md) independently. Hardware-required enrollment may correctly reject
devices/browsers that omit attestation, return unknown models, use unapproved roots, have unsafe signed status or offer
backup-eligible/unsupported protection. Do not weaken the policy to mark those cases successful.

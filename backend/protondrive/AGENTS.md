# Proton Drive backend — maintenance notes

This backend is a pure-Go implementation against the official Proton Drive REST
API.  It does **not** use any community-maintained Proton API libraries.

## Key dependencies

| Package | Purpose |
|---------|---------|
| `github.com/ProtonMail/gopenpgp/v2` | All PGP crypto (keys, encrypt, decrypt, sign) |
| `github.com/ProtonMail/go-srp` | SRP authentication + mailbox password derivation |
| `net/http` (stdlib) + `github.com/rclone/rclone/fs/fshttp` | HTTP transport |

## Authoritative reference (read-only)

The canonical source of truth for API shapes and crypto behaviour is the
official Proton Drive SDK (read-only):

  https://github.com/ProtonDriveApps/sdk/tree/main/js/sdk/src/internal/

Key files:

| File | Purpose |
|------|---------|
| `nodes/apiService.ts` | move/rename request fields, Code 2000 handling |
| `apiService/driveTypes.ts` | all API type definitions |
| `upload/apiService.ts` | commit revision, request block upload |
| `upload/cryptoService.ts` | block encryption / verification token |
| `upload/blockVerifier.ts` | `verificationToken = verificationCode XOR encryptedData` |
| `shares/cryptoService.ts` | share passphrase, volume bootstrap |

When the server returns an unexpected error, always cross-check the OpenAPI
types in `driveTypes.ts` before guessing at the fix.

## API basics

- **Base URL**: `https://drive-api.proton.me`
- **App-version header**: `x-pm-appversion: external-drive-rclone@1.0.0`
- All drive endpoints use the **v2 volume-based** paths:
  `GET/POST /drive/v2/volumes/{volumeID}/…`
- Authentication: SRP → `POST /auth/v4`; token refresh via `POST /auth/v4/refresh`.

## Crypto chain (unlock order)

```
saltedKeyPass
  └─ userKR          (unlocked user private key)
       └─ addrKR     (token-based: decrypt Token with userKR, use as passphrase)
            └─ shareKR  (decrypt share Passphrase with addrKR)
                 └─ rootNodeKR  (decrypt root link NodePassphrase with shareKR)
                      └─ childNodeKR  (decrypt child NodePassphrase with parentNodeKR)
                           └─ …
```

- **Token-based address keys** (modern accounts): `AddressKey.Token` is a PGP
  message encrypted to the user key.  Decrypt with `userKR` to get the
  passphrase for `AddressKey.PrivateKey`.
- **`unlockNodeKey` fallback**: try `Decrypt(msg, addrKR, …)` first; if that
  fails, retry with `Decrypt(msg, nil, …)` (no signature verification).  Root
  link passphrases may have no inline signature.
- **Name hash key**: always decrypt the *parent's* `FolderData.NodeHashKey`
  (using the parent's node keyring), not the new node's.  The HMAC key belongs
  to the parent folder.

## File upload flow

1. Generate node key pair → encrypt passphrase to parent KR → sign with addrKR.
2. Generate session key → wrap as `ContentKeyPacket` (encrypted to node KR).
3. Create file draft: `POST /drive/v2/volumes/{volumeID}/files`.
4. Fetch verification code: `GET …/links/{linkID}/revisions/{revisionID}/verification`.
5. Encrypt each 4 MiB block with the session key.
6. Compute per-block verification token: `token[i] = verificationCode[i] XOR encryptedData[i]`
   (zero-pad if `encryptedData` is shorter; `verificationCode` is base64-decoded first).
7. Request upload URLs: `POST /drive/blocks` with `BlockList`.
8. Upload each block: **`POST`** to `BareURL` as `multipart/form-data`, field
   name `Block`, filename `blob`, header `pm-storage-token: <token>`.
9. Sign the manifest (concatenated raw SHA-256 bytes of all blocks) with addrKR.
10. Commit revision: `PUT …/files/{linkID}/revisions/{revisionID}` with
    `ManifestSignature`, `XAttr` (encrypted), `State: 1`.

## Move / rename

- Endpoint: `PUT /drive/v2/volumes/{volumeID}/links/{linkID}/move`
- **`OriginalHash`** is required — pass `srcLink.Link.NameHash` from the batch
  link response.
- **`ContentHash`** must be sent explicitly as JSON `null` (not omitted).  In
  Go the struct field is `*string` with tag `json:"ContentHash"` (no
  `omitempty`), and the value is `nil`.
- The rename endpoint (`…/rename`) uses the same `MoveLinkReq` struct but
  sends `OriginalHash: <hash> | null` and no `ParentLinkID`.

### Session key reuse (critical)

The Proton Drive API (`MoveLinkRequestDto2` in `driveTypes.ts`) requires that
the **same session key** used in the original encryption is reused for both the
node passphrase and the node name when moving or renaming.  Generating a new
session key causes the server to return **Code 2000** ("maybe outdated app").

- **`reEncryptPassphrase`** (`crypto.go`): splits the armored passphrase into
  key packet + data packet, decrypts the session key from the key packet using
  `srcParentKR` (fallback to `addrKR`, then `userKR`), re-encrypts the same
  session key to `dstParentKR`, and reassembles with the original data packet.
- **`reEncryptName`** (`crypto.go`): decrypts the session key from the old name
  key packet, then calls `sk.EncryptAndSign(newNamePlaintext, addrKR)` to
  produce a new data packet with the same session key, then re-encrypts the
  session key to `dstParentKR` for the new key packet.

### Anonymous vs non-anonymous nodes

The SDK (`nodesManagement.ts` lines 164–170) distinguishes between anonymous
nodes (`keyAuthor === null`) and non-anonymous nodes:

- **`NodePassphraseSignature`** and **`SignatureEmail`**: send **only** for
  anonymous nodes.  Sending them for non-anonymous nodes causes **Code 2000**.
- **`NameSignatureEmail`**: always required; send for all nodes.

In Go: omit `NodePassphraseSignature` and `SignatureEmail` from `MoveLinkReq`
entirely (zero-value `string` fields with no `omitempty` must be converted to
pointer fields omitted when nil, or simply not set).

### Code 2000

`Code 2000` = "maybe outdated app" = generic server validation error.  In the
context of move/rename it almost always means one of:

1. A new session key was generated instead of reusing the original.
2. `NodePassphraseSignature` or `SignatureEmail` were sent for a non-anonymous
   node.

## SetModTime

Returns `fs.ErrorCantSetModTime` — not implemented.  Modification time is
stored in the encrypted `XAttr` of the active revision; updating it would
require creating a new revision, which is out of scope.

## Event poller

A background goroutine polls `GET /drive/v2/volumes/{volumeID}/events/{eventID}`
every 30 s.  On any link event it flushes both the `dircache` and the
`linkKRCache` so that stale metadata is not served to callers.

## Integration tests

Environment variables required:

```
RCLONE_CONFIG_TESTPROTONDRIVE_USERNAME=<email>
RCLONE_CONFIG_TESTPROTONDRIVE_PASSWORD=<password>   # rclone-obscured
RCLONE_CONFIG_TESTPROTONDRIVE_REPLACE_EXISTING_DRAFT=true
```

**Test runtime and pacing**

- The full integration suite takes roughly **5–10 minutes** in normal conditions (observed ~5m30s on a local run). Network latency and Proton API load can push this higher.
- Every API call — including event polling — is serialised through the backend pacer by design. This keeps rclone within Proton's desired request rates; it also means tests are slower than backends that fire requests in parallel.
- _If tests appear to hang or terminate early, use a higher timeout._ `-timeout 30m` gives ample headroom.
- Do not run multiple integration test jobs against the same Proton account simultaneously; the pacer is per-process and concurrent jobs will race on shared account state.

Run with:

```
go test ./backend/protondrive/ -run TestIntegration -timeout 30m -count=1 -v
```

Use `-run TestIntegration/FsMove` etc. to target individual sub-tests.

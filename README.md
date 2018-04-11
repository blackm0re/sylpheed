Implemented features and fixes not present in the official Sylpheed release
===========================================================================

- (fix)
  PGP signature not verified properly when the message has no newline
  at the end. https://sylpheed.sraoss.jp/redmine/issues/288

- (feature)
  Make it possible to select "Show signature check result in a popup window"
  only for bad signatures.

- (feature)
  Support for encrypting and storing encrypted passwords using a master password.
  See README for more details.


Master password
===============

The master password feature is developed by Simeon Simeonov (sgs)
and is currently in an experimental state.


Motivation
----------

Currently Sylpheed is storing passwords in palin-text. One can always refrain
from storing passwords and let Sylpheed prompt for them, but the more accounts
one has, the more annoying this becomes.

The goal is to have the passwords stored in a secure way and let Sylpheed only
prompt for the master password.


Security goals
--------------

- attacker (A) should not be able to derive the password from the digest

- A should not be able to derive the master password even if she has
  read and write access to the storage

- A should not be able to determine the length of the encrypted password
  even if she has read and write access to the storage

- A should not be able to craft an edited password without obtaining the
  master password

- a warning / prompt should be given if a user accidently types in a "wrong"
  master password before decryption is initiated


Usage in Sylpheed
-----------------

- backup your Sylpheed profile (often $HOME/.sylpheed-2.0)!

- start Sylpheed and open Configuration -> Common preferences...!

- select the "Master password" tab, enable "Use master password" and
  apply the changes!

- restart Sylpheed (exit and then start Sylpheed again)!

- you will be asked to type and verify a new master password.

Note:
Sylpheed will automatically convert existing stored passwords, but it will not
touch your backups. You will have to remove all remnants of plain-text
passwords manually.


Choice of cryptographic primitives
----------------------------------

The primary concern when selecting cryptographic primitives was portability.
The desire was to go for primitives that are both strong and available in all
supported production distributions of OpenSSL and LibreSSL.


Cipher
......

When it comes to implementation, there are several advantages in using stream
cipher or a block cipher that behaves like a stream cipher when used in a
certain mode of operation. One is avoiding to deal with padding.

AES-256 operating in CFB was selected for these reasons.
ChaCha20 should be considered as a replacement in the future.


Hash-function
.............

Hash-functions are used for:
- key derivation
- plain-text digest

Those operations do not have to use the same hash-function.
(See the "Encryption & decryption scheme" section for more details!)

Key-derivation:
Since AES-256 uses a 256 bits key, we need a hash-function with at least
the same digest size or bigger.
Since the digest (which is the key itself) is considered confidential and is
stored only in memory for only a limited amount of time, SHA-256 is considered
sufficiently strong for that purpose.

Size + plain-text + padding digest:
Since the digest is created of both the plain-text and the plain-text size,
as well as being encrypted, SHA-256 is considered sufficiently strong.
SHA-512 may increase security at the price of adding additional 32 bytes
to the encrypted password digest.

Stronger hash-functions like SHA-3 or BLAKE2b can be considered as a
replacement in the future.


Master password digest
......................

In order to be able to decide whether the user typed a "wrong" master password,
before attempting to decrypt, Sylpheed stores a digest of the master password
in 'master_password_hash' in sylpheedrc.
100000 iterations of PBKDF2_HMAC with SHA-512 and 16 bytes salt is used.
Note that this digest is useless as a key and even if a plain-text that
produces the same digest is found, it will most probably be useless as a
master-password.


Encryption & decryption scheme
------------------------------


Encryption
..........


Input:

- palin-text password to be encrypted (P)

- plain-text master-password used for key derivation (M)

- integer minimum password length (0 < L < 100)


Output:

- an encrypted password digest (base64) (B)


Operation:

- generate 16 bytes of random data to be used as a salt (S)

- derive the key (K): K = SHA_256(S + M)

- produce a 2 byte string (N) indicating the length of P

- if the length of P < L, produce L - P bytes of random data (R), N = "%02d"
  if the length of P >= L, N = "-1"

- produce a hash digest (H): H = SHA_256(N + P + R (if the length of P < L))

- encrypt (E): E = AES_256_CFB_ENCRYPT(H + N + P + R (if the length of P < L), K)

- B = mpes1:BASE64_ENCODE(S + E)
  example:
  mpes1:vo7lsIpD7i6byBA6+vlUoF4OVDfEe+aYRRk4FRtfJ2gMY8M43Kj6WfdfgbViIOl83bI4XEc96okhPW5Mla813aAR1gbPjDg0xmCyIbWOiUv/dg==


Decryption
..........


Input:

- encrypted password digest (base64) (B)

- plain-text master-password used for key derivation (M)


Output:

- palin-text password (P)


Operation:

- remove the prefix (mpes1:) and base64-decode the rest of the digest: B = BASE64_DECODE(B)

- fetch the first 16 bytes for the salt: S = B[0 : 15]

- derive the key (K): K = SHA_256(S + M)

- decrypt the rest of B (D): D = AES_256_CFB_DECRYPT(B[16 :], K)

- extract the first 16 bytes for the hash digest (H): H = D[0 : 15]

- in order to detect data-inconsistency, assert H == SHA_256(D[16 :])

- extract the next 2 bytes for the length of P (N): N = D[16 : 17]

- if N == "-1" the password is the remaining bytes of D: P = D[18 :]
  if N != "-1", extract the next N-bytes from D: P = D[18 : (18 + N)]


Limitations
-----------

- when Sylpheed starts, the master-password is loaded into memory and remains
  there as long as Sylpheed is running. Currently no strong mechanisms,
  preventing someone with access to the memory from snatching it,
  are implemented.
  "Unloading" the master-password immediately after
  account-processing (decryption) should be considered in the future.

- currently only the 'password' and 'smtp_password' keys in accountrc
  are encrypted.
  A machanism that allows for any key and even folders to be encrypted
  should be considered in the future.

- currently it is not possible to select alternative ciphers, hash-functions
  and modes of operation (without editing the source code).

- currently it is not possible to change your master password without having to
  set your passwords manually.

-- 
Simeon Simeonov <sgs [ATTT] pichove (DOTTT) org>

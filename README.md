# fc-appkey

A standalone tool to generate Farcaster application keys (signers).

**This is a Go port of @stevedylandev's https://github.com/stevedylandev/cast-keys.**

## What it does

Generates a new ed25519 keypair and requests approval from Farcaster via Warpcast.

The tool will:
1. Generate a new ed25519 keypair
2. Create an EIP-712 signed key request using your developer credentials
3. Display an approval URL and QR code
4. Poll for user approval (up to 10 minutes)
5. Display the approved key credentials

## Prerequisites

You need:
- Your developer/app FID
- Your developer account mnemonic phrase (12-24 words)

## Usage

### Using environment variables (recommended for security):

```bash
export FC_DEVELOPER_FID=280
export FC_DEVELOPER_MNEMONIC="word1 word2 word3 ..."
fc-appkey
```

### Using interactive prompts:

```bash
fc-appkey
```

The tool will prompt you for:
- Developer FID
- Developer mnemonic phrase

## Installation

### Homebrew (macOS and Linux)

```bash
brew tap vrypan/tap
brew install fc-appkey
```

### Download Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/vrypan/fc-appkey/releases).

### Build from Source

```bash
git clone https://github.com/vrypan/fc-appkey.git
cd fc-appkey
go build -o fc-appkey
```

## Output

The tool displays:
- Generated public and private keys
- Approval URL
- QR code (scan with your phone)
- Real-time polling status
- Final approved FID and keys

Example output:
```
fc-appkey - Farcaster Application Key Generator
================================================

Using developer FID from environment: 280
Using developer mnemonic from environment

Generating new ed25519 keypair...
Public key:  0x...
Private key: 0x...

Deriving Ethereum address from mnemonic...
Developer address: 0x...

Submitting signed key request to Warpcast...

✓ Signed key request created!
Token: abc123...
Approval URL: https://warpcast.com/...

Scan this QR code with your phone to approve:
[QR CODE]

Waiting for approval...
..........
✓ Key approved by FID 12345!

=== Save these values ===
FID: 12345
Public Key:  0x...
Private Key: 0x...

You can now use this private key with Farcaster applications.
```

## Security Notes

- Keep your mnemonic phrase secure
- Store generated private keys safely
- Use environment variables for automated setups
- Never commit mnemonics or private keys to version control

## Environment Variables

- `FC_DEVELOPER_FID`: Your developer/app FID
- `FC_DEVELOPER_MNEMONIC`: Your developer account mnemonic phrase

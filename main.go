package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/skip2/go-qrcode"
	"github.com/tyler-smith/go-bip39"
)

// Version will be set at build time via -ldflags
var Version = "dev"

type SignedKeyRequestResponse struct {
	Result struct {
		SignedKeyRequest struct {
			Token       string `json:"token"`
			DeeplinkUrl string `json:"deeplinkUrl"`
		} `json:"signedKeyRequest"`
	} `json:"result"`
}

type PollResponse struct {
	Result struct {
		SignedKeyRequest struct {
			State   string `json:"state"`
			UserFid int    `json:"userFid"`
		} `json:"signedKeyRequest"`
	} `json:"result"`
}

func main() {
	// Check for version flag
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("fc-appkey version %s\n", Version)
		os.Exit(0)
	}

	// Check for help flag
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		printHelp()
		os.Exit(0)
	}

	fmt.Println("fc-appkey - Farcaster Application Key Generator")
	fmt.Println("================================================\n")

	// Get developer FID
	var devFid int
	fidStr := os.Getenv("FC_DEVELOPER_FID")
	if fidStr != "" {
		var err error
		devFid, err = strconv.Atoi(fidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid FC_DEVELOPER_FID: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Using developer FID from environment: %d\n", devFid)
	} else {
		fmt.Print("Enter your developer FID: ")
		reader := bufio.NewReader(os.Stdin)
		fidInput, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
		devFid, err = strconv.Atoi(strings.TrimSpace(fidInput))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid FID: %v\n", err)
			os.Exit(1)
		}
	}

	// Get developer mnemonic
	var devMnemonic string
	devMnemonic = os.Getenv("FC_DEVELOPER_MNEMONIC")
	if devMnemonic != "" {
		fmt.Println("Using developer mnemonic from environment")
	} else {
		fmt.Print("Enter your developer mnemonic phrase: ")
		reader := bufio.NewReader(os.Stdin)
		mnemonicInput, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
		devMnemonic = strings.TrimSpace(mnemonicInput)
	}

	// Validate mnemonic
	if !bip39.IsMnemonicValid(devMnemonic) {
		fmt.Fprintf(os.Stderr, "Error: Invalid mnemonic phrase\n")
		os.Exit(1)
	}

	fmt.Println("\nGenerating new ed25519 keypair...")
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	publicKeyHex := "0x" + hex.EncodeToString(publicKey)
	privateKeyHex := "0x" + hex.EncodeToString(privateKey.Seed())

	fmt.Printf("Public key:  %s\n", publicKeyHex)
	fmt.Printf("Private key: %s\n", privateKeyHex)

	// Derive Ethereum account from mnemonic
	fmt.Println("\nDeriving Ethereum address from mnemonic...")
	seed, err := bip39.NewSeedWithErrorChecking(devMnemonic, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating seed: %v\n", err)
		os.Exit(1)
	}

	ethPrivateKey, err := derivePrivateKey(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving private key: %v\n", err)
		os.Exit(1)
	}

	account := crypto.PubkeyToAddress(ethPrivateKey.PublicKey)
	fmt.Printf("Developer address: %s\n", account.Hex())

	// Create EIP-712 signature
	deadline := time.Now().Unix() + 86400 // 24 hours from now

	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SignedKeyRequest": []apitypes.Type{
				{Name: "requestFid", Type: "uint256"},
				{Name: "key", Type: "bytes"},
				{Name: "deadline", Type: "uint256"},
			},
		},
		PrimaryType: "SignedKeyRequest",
		Domain: apitypes.TypedDataDomain{
			Name:              "Farcaster SignedKeyRequestValidator",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(10),
			VerifyingContract: "0x00000000fc700472606ed4fa22623acf62c60553",
		},
		Message: apitypes.TypedDataMessage{
			"requestFid": math.NewHexOrDecimal256(int64(devFid)),
			"key":        publicKeyHex,
			"deadline":   math.NewHexOrDecimal256(deadline),
		},
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing domain: %v\n", err)
		os.Exit(1)
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing typed data: %v\n", err)
		os.Exit(1)
	}

	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	signHash := crypto.Keccak256Hash(rawData)

	signature, err := crypto.Sign(signHash.Bytes(), ethPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
		os.Exit(1)
	}

	// Adjust V value for Ethereum signature
	if signature[64] < 27 {
		signature[64] += 27
	}

	signatureHex := "0x" + hex.EncodeToString(signature)

	// POST to Warpcast API
	fmt.Println("\nSubmitting signed key request to Warpcast...")
	requestBody := map[string]interface{}{
		"key":        publicKeyHex,
		"signature":  signatureHex,
		"requestFid": devFid,
		"deadline":   deadline,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling request: %v\n", err)
		os.Exit(1)
	}

	resp, err := http.Post(
		"https://api.warpcast.com/v2/signed-key-requests",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error posting to Warpcast API: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Warpcast API returned status %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var signedKeyResp SignedKeyRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&signedKeyResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding response: %v\n", err)
		os.Exit(1)
	}

	token := signedKeyResp.Result.SignedKeyRequest.Token
	approvalUrl := signedKeyResp.Result.SignedKeyRequest.DeeplinkUrl

	fmt.Printf("\n✓ Signed key request created!\n")
	fmt.Printf("Token: %s\n", token)
	fmt.Printf("Approval URL: %s\n\n", approvalUrl)

	// Generate QR code
	qr, err := qrcode.New(approvalUrl, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating QR code: %v\n", err)
		os.Exit(1)
	}

	// Display QR code in terminal
	fmt.Println("Scan this QR code with your phone to approve:")
	fmt.Println(qr.ToSmallString(false))

	// Poll for approval
	fmt.Println("\nWaiting for approval...")
	userFid, err := pollForApproval(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Key approved by FID %d!\n\n", userFid)
	fmt.Println("=== Save these values ===")
	fmt.Printf("FID: %d\n", userFid)
	fmt.Printf("Public Key:  %s\n", publicKeyHex)
	fmt.Printf("Private Key: %s\n", privateKeyHex)
	fmt.Println("\nYou can now use this private key with Farcaster applications.")
}

// derivePrivateKey derives an Ethereum private key from a BIP-39 seed
// using the standard Ethereum derivation path m/44'/60'/0'/0/0
func derivePrivateKey(seed []byte) (*ecdsa.PrivateKey, error) {
	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive path m/44'/60'/0'/0/0
	// m/44'
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose: %w", err)
	}

	// m/44'/60'
	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 60)
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type: %w", err)
	}

	// m/44'/60'/0'
	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account: %w", err)
	}

	// m/44'/60'/0'/0
	change, err := account.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change: %w", err)
	}

	// m/44'/60'/0'/0/0
	addressKey, err := change.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the private key
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get EC private key: %w", err)
	}

	return privKey.ToECDSA(), nil
}

func pollForApproval(token string) (int, error) {
	maxAttempts := 120 // 10 minutes with 5 second intervals
	for i := 0; i < maxAttempts; i++ {
		time.Sleep(5 * time.Second)

		resp, err := http.Get(fmt.Sprintf("https://api.warpcast.com/v2/signed-key-request?token=%s", token))
		if err != nil {
			continue // Retry on error
		}

		var pollResp PollResponse
		if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		state := pollResp.Result.SignedKeyRequest.State
		fmt.Printf(".")

		if state == "completed" {
			fmt.Println()
			return pollResp.Result.SignedKeyRequest.UserFid, nil
		}

		if state == "rejected" {
			return 0, fmt.Errorf("key request was rejected")
		}
	}

	return 0, fmt.Errorf("timeout waiting for approval")
}

func printHelp() {
	fmt.Println("fc-appkey - Farcaster Application Key Generator")
	fmt.Println()
	fmt.Println("Generate a new Farcaster application key (signer) with proper EIP-712 signing")
	fmt.Println("and automatic approval via Warpcast.")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  fc-appkey [--help] [--version]")
	fmt.Println()
	fmt.Println("DESCRIPTION:")
	fmt.Println("  This tool generates a new ed25519 keypair for Farcaster applications and")
	fmt.Println("  guides you through the approval process.")
	fmt.Println()
	fmt.Println("  The tool will:")
	fmt.Println("    1. Generate a new ed25519 keypair")
	fmt.Println("    2. Create an EIP-712 signed key request using your developer credentials")
	fmt.Println("    3. Display an approval URL and QR code")
	fmt.Println("    4. Poll for user approval (up to 10 minutes)")
	fmt.Println("    5. Display the approved key credentials")
	fmt.Println()
	fmt.Println("ENVIRONMENT VARIABLES:")
	fmt.Println("  FC_DEVELOPER_FID")
	fmt.Println("      Your developer/app Farcaster ID (FID)")
	fmt.Println("      If not set, you will be prompted interactively")
	fmt.Println()
	fmt.Println("  FC_DEVELOPER_MNEMONIC")
	fmt.Println("      Your developer account mnemonic phrase (12-24 words)")
	fmt.Println("      If not set, you will be prompted interactively")
	fmt.Println("      Keep this secure - never commit it to version control")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Using environment variables (recommended for automation)")
	fmt.Println("  export FC_DEVELOPER_FID=280")
	fmt.Println("  export FC_DEVELOPER_MNEMONIC=\"word1 word2 word3 ...\"")
	fmt.Println("  fc-appkey")
	fmt.Println()
	fmt.Println("  # Interactive mode (will prompt for FID and mnemonic)")
	fmt.Println("  fc-appkey")
	fmt.Println()
	fmt.Println("PREREQUISITES:")
	fmt.Println("  - A Farcaster account with a developer FID")
	fmt.Println("  - The mnemonic phrase for your developer account")
	fmt.Println()
	fmt.Println("OUTPUT:")
	fmt.Println("  The tool will display:")
	fmt.Println("    - Generated public and private keys")
	fmt.Println("    - Approval URL (for manual access)")
	fmt.Println("    - QR code (scan with your phone to approve)")
	fmt.Println("    - Approved FID and final key credentials")
	fmt.Println()
	fmt.Println("  Save the private key securely - you'll need it for your application.")
	fmt.Println()
	fmt.Println("SECURITY:")
	fmt.Println("  - Keep your mnemonic phrase secure")
	fmt.Println("  - Store generated private keys safely")
	fmt.Println("  - Use environment variables for automated setups")
	fmt.Println("  - Never commit mnemonics or private keys to version control")
}

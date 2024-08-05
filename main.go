package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"syscall"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/term"
)

type secretStore struct {
	Domain         string `json:"domain"`
	RelyingPartyID string `json:"relying-party-id"`
	Key            []byte `json:"key"`
	CredentialID   []byte `json:"credential-id"`
	UserID         []byte `json:"user-id"`
	SignCount      uint32 `json:"sign-count"`
}

func readCache() (*secretStore, error) {
	data, err := os.ReadFile("secret.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read secret.json: %v", err)
	}
	var result secretStore
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret.json: %w", err)
	}
	return &result, nil
}

func writeCache(s *secretStore) error {
	data, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal secret.json: %v", err)
	}
	err = os.WriteFile("secret.json", data, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("failed to write secret.json: %v", err)
	}
	return nil
}

func post(client *http.Client, domain string, urlStr string, jsonStr map[string]any) (map[string]any, error) {
	rb, err := json.Marshal(jsonStr)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HTTP request JSON: %v", err)
	}
	headers := http.Header{}
	headers.Add("Content-Type", "application/json")
	headers.Add("Accept", "application/json")
	u := domain + urlStr
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(rb))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Origin", domain)
	req.Body = io.NopCloser(bytes.NewReader(rb))
	fmt.Printf("POST %s\n", u)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close response body: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("bad status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result map[string]any
	err = json.Unmarshal(body, &result)
	if err != nil {
		var result []map[string]any
		err = json.Unmarshal(body, &result)
		if err != nil {
			return nil, fmt.Errorf("cannot unmarshal response %q: %v", body, err)
		}
		return result[0], nil
	}
	return result, nil
}

func makeAuthenticatorData(rpid string, signCount uint32, attestedCredData []byte) []byte {
	userPresenceFlag := byte(1)
	userVerifiedFlag := byte(1)
	backupEligibleFlag := byte(1)
	backupStateFlag := byte(1)
	attestedCredentialDataFlag := byte(0)
	if len(attestedCredData) > 0 {
		attestedCredentialDataFlag = 1
	}
	authDataFlags := userPresenceFlag | (userVerifiedFlag << 2) | (backupEligibleFlag << 3) | (backupStateFlag << 4) | (attestedCredentialDataFlag << 6)
	rpidHash := sha256.Sum256([]byte(rpid))
	authData := append(rpidHash[:], authDataFlags, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	if len(attestedCredData) > 0 {
		authData = append(authData, attestedCredData...)
	}
	return authData
}

func main() {
	cookieJar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	client := &http.Client{
		Jar: cookieJar,
	}

	s, err := readCache()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	if s == nil {
		fmt.Println("enter the domain you want to log in to (e.g. `https://pre.jellyfishhq.com`):")
		var domain string
		_, err = fmt.Scanln(&domain)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		if !strings.HasPrefix(domain, "https://") {
			fmt.Printf("domain must begin with `https://`\n")
			os.Exit(1)
		}
		domain = strings.TrimRight(domain, "/")

		fmt.Printf("please enter your username:\n")
		var username string
		_, err = fmt.Scanln(&username)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("please enter your password (note: multi-factor authentication is not supported):\n")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
		password := string(bytepw)
		loginInfo, err := post(client, domain, "/api2/Authentication-v1/login", map[string]any{
			"username": username,
			"password": password,
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		userId := loginInfo["id"].(string)
		fmt.Printf("successfully logged in with user ID %s\n", userId)
		startFido, err := post(client, domain, "/api2/Authentication-v1/PrepareFido2Registration", map[string]any{
			"userId": userId,
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		credentialCreationOptionsJson := startFido["credentialCreationOptionsJson"].(string)
		fidoSessionId := startFido["sessionId"].(string)
		var credentialCreationOptions map[string]any
		err = json.Unmarshal([]byte(credentialCreationOptionsJson), &credentialCreationOptions)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		rpid := credentialCreationOptions["publicKey"].(map[string]any)["rp"].(map[string]any)["id"].(string)
		fmt.Printf("Relying Party ID: %s\n", rpid)
		fidoUserId, err := base64.RawURLEncoding.DecodeString(credentialCreationOptions["publicKey"].(map[string]any)["user"].(map[string]any)["id"].(string))
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("FIDO user ID: %s\n", base64.StdEncoding.EncodeToString(fidoUserId))
		challenge, err := base64.RawURLEncoding.DecodeString(credentialCreationOptions["publicKey"].(map[string]any)["challenge"].(string))
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("FIDO registration challenge: %s\n", base64.StdEncoding.EncodeToString(challenge))

		clientDataJson, err := json.Marshal(map[string]any{
			"type":        "webauthn.create",
			"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
			"origin":      domain,
			"crossOrigin": false,
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("clientDataJSON: %s\n", string(clientDataJson))

		credentialId := make([]byte, 32)
		_, err = rand.Read(credentialId)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Credential ID: %s\n", base64.RawURLEncoding.EncodeToString(credentialId))

		aaguid := []byte{0x22, 0x14, 0xbb, 0x75, 0x1e, 0x17, 0x45, 0x88, 0xb3, 0x23, 0xa0, 0xa4, 0x93, 0x41, 0xef, 0xa6} // some random GUID

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		cosePubKey, err := cbor.Marshal(map[any]any{
			1:  1,  // kty: OKP (octet key pair)
			3:  -8, // alg: EdDSA
			-1: 6,  // crv: Ed25519
			-2: []byte(pub),
		})

		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("cose key: %v\n", hex.EncodeToString(cosePubKey))

		credIdLen := uint16(len(credentialId))
		attestedCredData := append(aaguid, byte(credIdLen>>8), byte(credIdLen))
		attestedCredData = append(attestedCredData, credentialId...)
		attestedCredData = append(attestedCredData, cosePubKey...)

		authData := makeAuthenticatorData(rpid, 1, attestedCredData)
		fmt.Printf("attested cred data: %v\n", hex.EncodeToString(authData))
		attestationObject, err := cbor.Marshal(map[string]any{
			"fmt":      "none",
			"attStmt":  map[string]any{},
			"authData": authData,
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("attestation object: %s\n", hex.EncodeToString(attestationObject))
		credentialCreationResponseJson, err := json.Marshal(map[string]any{
			"id":    base64.RawURLEncoding.EncodeToString(credentialId),
			"type":  "public-key",
			"rawId": base64.RawURLEncoding.EncodeToString(credentialId),
			"response": map[string]string{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJson),
				"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
			},
		})
		fmt.Printf("%s\n", credentialCreationResponseJson)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		finishFidoReg, err := post(client, domain, "/api2/Authentication-v1/FinishFido2Registration", map[string]any{
			"sessionId":                      fidoSessionId,
			"customName":                     "jf-passkey",
			"credentialCreationResponseJson": string(credentialCreationResponseJson),
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("successfully registered passkey!\n")
		count := len(finishFidoReg["registeredCredentials"].(map[string]any)["registeredCredentials"].([]any))
		fmt.Printf("note: you have %d total credential(s) registered to your account :)\n", count)
		fmt.Println("your credential is stored in `secret.json`")
		fmt.Println("run this program again to authenticate using this new passkey!")

		err = writeCache(&secretStore{
			Domain:         domain,
			Key:            []byte(priv),
			CredentialID:   credentialId,
			UserID:         fidoUserId,
			SignCount:      1,
			RelyingPartyID: rpid,
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("using existing credential for domain %s\n", s.Domain)
		startFido, err := post(client, s.Domain, "/api2/Authentication-v1/PrepareFido2Authentication", map[string]any{})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		credentialAuthenticationOptionsJson := startFido["credentialAuthenticationOptionsJson"].(string)
		fidoSessionId := startFido["sessionId"].(string)
		var credentialAuthenticationOptions map[string]any
		err = json.Unmarshal([]byte(credentialAuthenticationOptionsJson), &credentialAuthenticationOptions)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		rpid := credentialAuthenticationOptions["publicKey"].(map[string]any)["rpId"].(string)
		if rpid != s.RelyingPartyID {
			fmt.Printf("relying party ID from server ('%s') does not match relying party ID from secret.json ('%s')\n", rpid, s.RelyingPartyID)
			os.Exit(1)
		}
		fmt.Printf("Relying party ID: %s\n", rpid)
		challenge, err := base64.RawURLEncoding.DecodeString(credentialAuthenticationOptions["publicKey"].(map[string]any)["challenge"].(string))
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("FIDO authentication challenge: %s\n", base64.StdEncoding.EncodeToString(challenge))

		clientDataJson, err := json.Marshal(map[string]any{
			"type":        "webauthn.get",
			"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
			"origin":      s.Domain,
			"crossOrigin": false,
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("clientDataJSON: %s\n", string(clientDataJson))

		s.SignCount += 1
		err = writeCache(s)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		authenticatorData := makeAuthenticatorData(rpid, s.SignCount, nil)

		clientDataHash := sha256.Sum256(clientDataJson)
		signature := ed25519.Sign(ed25519.PrivateKey(s.Key), append(authenticatorData, clientDataHash[:]...))
		fmt.Printf("signature: %s\n", base64.RawURLEncoding.EncodeToString(signature))

		credentialAuthenticationResponseJson, err := json.Marshal(map[string]any{
			"id":    base64.RawURLEncoding.EncodeToString(s.CredentialID),
			"type":  "public-key",
			"rawId": base64.RawURLEncoding.EncodeToString(s.CredentialID),
			"response": map[string]string{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJson),
				"authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData),
				"signature":         base64.RawURLEncoding.EncodeToString(signature),
				"userHandle":        base64.RawURLEncoding.EncodeToString(s.UserID),
			},
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		_, err = post(client, s.Domain, "/api2/Authentication-v1/FinishFido2Authentication", map[string]any{
			"sessionId":                            fidoSessionId,
			"credentialAuthenticationResponseJson": string(credentialAuthenticationResponseJson),
		})
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("successfully authenticated with passkey :)\n")
	}
}

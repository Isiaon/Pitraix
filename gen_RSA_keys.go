package main

import (
	"crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
	// "reflect"
    "fmt"
)
 
func main() {
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
		fmt.Println(err)
	}
	// fmt.Println(privateKey)

 
    publicKey := privateKey.PublicKey
    secretMessage := "This is super secret message!"
	
    encryptedMessage := RSA_OAEP_Encrypt(secretMessage, publicKey)
	RSA_OAEP_Decrypt(encryptedMessage, *privateKey)


	signature, msgHashSum, err := create_signature([]byte("yo lol"), *privateKey) // rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		fmt.Println(err)
	}

	verify := verify_signature(publicKey, msgHashSum, signature)
	if verify != nil {
		fmt.Println("failed to verify signature", verify)
	} else {
		fmt.Println("verified", verify)
	}

	
}

func create_signature(msg []byte, privateKey rsa.PrivateKey) ([]byte, []byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write(msg)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	msgHashSum := msgHash.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, &privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	
	return signature, msgHashSum, nil
}
func verify_signature(publicKey rsa.PublicKey, msgHashSum []byte, signature []byte) error {
	err := rsa.VerifyPSS(&publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		return err
	}

	return nil
}

func RSA_OAEP_Encrypt(secretMessage string, publicKey rsa.PublicKey) string {
    rng := rand.Reader
    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &publicKey, []byte(secretMessage), nil)
	if err != nil {
        fmt.Println(err)
    }
    return base64.StdEncoding.EncodeToString(ciphertext)
}
 
func RSA_OAEP_Decrypt(cipherText string, privateKey rsa.PrivateKey) string {
    ct, _ := base64.StdEncoding.DecodeString(cipherText)
    rng := rand.Reader
    plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privateKey, ct, nil)
    if err != nil {
        fmt.Println(err)
    }
    return string(plaintext)
}
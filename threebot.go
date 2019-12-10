package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"errors"

	"net/url"

	"net/http"

	"github.com/GoKillers/libsodium-go/cryptosign"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/box"
	"github.com/kevinburke/nacl/sign"
)

type UserStruct struct {
	PublicKey string `json:"publicKey"`
}

type ThreebotDataStruct struct {
	Nonce      string `json:"nonce"`
	CipherText string `json:"ciphertext"`
}

type ThreebotResultStruct struct {
	Email struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	}
}

func getKeys() (sign.PublicKey, sign.PrivateKey, error) {
	seed := "aKQ1v9QAy9iq1o3ZSzyIgJT6qVZ4wASnxvfLKtIEHp0="
	reader := strings.NewReader(seed)

	pub, priv, err := sign.Keypair(reader)
	if err != nil {
		return nil, nil, err
	}

	pub, exit := cryptosign.CryptoSignEd25519PkToCurve25519(pub)
	if exit > 0 {
		return nil, nil, errors.New("error converting public key to curve")

	}

	priv, exit = cryptosign.CryptoSignEd25519SkToCurve25519(priv)

	if exit > 0 {
		return nil, nil, errors.New("error converting public key to curve")

	}

	return pub, priv, nil

}

func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Internal Server Error"))
	fmt.Println(err)
}

func login(w http.ResponseWriter, r *http.Request) {

	redirectURL := "https://login.threefold.me"
	state, err := uuid.NewUUID()

	if err != nil {
		handleError(w, err)
	}

	pub, _, err := getKeys()
	pub64 := base64.StdEncoding.EncodeToString(pub)

	if err != nil {
		handleError(w, err)
	}

	stateString := strings.Replace(state.String(), "-", "", -1)
	fmt.Println(stateString)

	// @TODO: Put state in session

	params := url.Values{}
	params.Add("state", stateString)
	params.Add("redirecturl", "/api/callback")
	params.Add("scope", `{"user": true, "email": true}`)
	params.Add("publickey", pub64)
	params.Add("appid", r.Host)
	http.Redirect(w, r, redirectURL+"?"+params.Encode(), 302)
}

func callback(w http.ResponseWriter, r *http.Request) {
	threebotURL := "https://login.threefold.me/api/users/"
	queryValues := r.URL.Query()
	username := queryValues.Get("username")
	signedHash := queryValues.Get("signedhash")
	data := queryValues.Get("data")

	dataStruct := ThreebotDataStruct{}
	userStruct := UserStruct{}

	if signedHash == "" || username == "" || data == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("One or more required parameters is missing"))
		return
	}

	signedHashBytes, err := base64.StdEncoding.DecodeString(signedHash)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Can not decode signed hash"))
		return
	}

	signedHash = string(signedHashBytes)

	err = json.Unmarshal([]byte(data), &dataStruct)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error decoding data parameter -- not JSON"))
		return
	}

	if dataStruct.Nonce == "" || dataStruct.CipherText == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error decoding data parameter -- not JSON"))
		return
	}

	resp, err := http.Get(threebotURL + username)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error getting user public key"))
		return
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&userStruct)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error decoding user public key response from threebot server -- not json"))
		return
	}

	userPubKey64, err := base64.StdEncoding.DecodeString(userStruct.PublicKey)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error decoding user public key not base64 encoded"))
		return
	}

	userPublicKey := sign.PublicKey(userPubKey64)

	verified := userPublicKey.Verify([]byte(signedHash))

	if !verified {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Data Verification failed"))
		return
	}

	stateBytes := signedHash[sign.SignatureSize:]
	state := string(stateBytes)
	fmt.Println(state)
	fmt.Println("---")

	// @TODO: get state from session and compare against this state

	nonceBytes, err := base64.StdEncoding.DecodeString(dataStruct.Nonce)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Can not decode nonce"))
		return
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(dataStruct.CipherText)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Can not decode ciphertext"))
		return
	}

	_, priv, err := getKeys()

	if err != nil {
		handleError(w, err)
		return
	}

	userPublicKeyCurve, exit := cryptosign.CryptoSignEd25519PkToCurve25519(userPublicKey)

	if exit > 0 {
		handleError(w, errors.New("error converting public key to curve"))
	}
	var nonce [nacl.NonceSize]byte
	copy(nonce[:], nonceBytes[:nacl.NonceSize])

	var naclPubKey [nacl.KeySize]byte
	copy(naclPubKey[:], userPublicKeyCurve)

	var naclPrivKey [nacl.KeySize]byte
	copy(naclPrivKey[:], priv)

	decrypted, ok := box.Open(nil, cipherBytes, &nonce, &naclPubKey, &naclPrivKey)

	if !ok {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error decrypting text"))
		return
	}

	var threebotResult ThreebotResultStruct
	err = json.Unmarshal(decrypted, &threebotResult)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error decoding result coming from 3 bot"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)

	result, err := json.Marshal(&threebotResult)

	w.Write(result)
}

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/").Subrouter()
	api.HandleFunc("/login", login).Methods(http.MethodGet)
	api.HandleFunc("/callback", callback).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}

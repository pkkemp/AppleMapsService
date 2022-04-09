package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Create the JWT key used to create the signature
var rawJwtKey []byte
var mapsKey *ecdsa.PrivateKey

var mapsKeyID = "ZA2Y7ZR45P"

//JWT Claims required by MapKitJS
type Claims struct {
	Issuer   string `json:"iss"`
	IssuedAt int64  `json:"iat"`
	KeyID    string `json:"kid"`
	Origin   string `json:"origin"`
	jwt.StandardClaims
}

//Generate MapKitJS Token
func GenerateMapsToken(w http.ResponseWriter, r *http.Request) {
	sites, ok := r.URL.Query()["site"]
	if !ok || len(sites[0]) < 1 {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Url Param 'Site' is missing")
		return
	}

	// Query()["key"] will return an array of items,
	// we only want the single item.
	site := sites[0]

	//validate if this is a URL we should provide a signed token for
	URLComponents := strings.Split(site, ".")
	numComponents := len(URLComponents)
	if URLComponents[numComponents-1] != "org" || URLComponents[numComponents-1] != "dev" ||
		(URLComponents[numComponents-2] != "freemomhugs" &&
			URLComponents[numComponents-2] != "https://freemomhugs") {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("Invalid Site")
		return
	}

	var claims Claims
	claims.IssuedAt = time.Now().Unix()
	claims.Issuer = "6G53WHVXA8"

	claims.Origin = site
	//set the token to expire 30 minutes from now
	claims.ExpiresAt = time.Now().Add(30 * time.Minute).Unix()

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = mapsKeyID
	// Create the JWT string
	tokenString, err := token.SignedString(mapsKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: time.Now().Add(30 * time.Minute),
	})
	w.Header().Set("Access-Control-Allow-Origin", site)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(tokenString))
}

func main() {
	p8bytes, err := ioutil.ReadFile("AuthKey_ZA2Y7ZR45P.p8")
	if err != nil {
		log.Println(err)
		return
	}

	// Decode the Maps private key, which is in pem format
	block, _ := pem.Decode(p8bytes)
	// Check if it's a private key
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Println("Failed to decode PEM block containing private key")
		return
	}
	// Get the encoded bytes
	x509Encoded := block.Bytes

	// stuff the parsed key into *ecdsa.PrivateKey
	parsedKey, err := x509.ParsePKCS8PrivateKey(x509Encoded) // EDIT to x509Encoded from p8bytes
	if err != nil {
		panic(err)
	}

	var ok bool
	mapsKey, ok = parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		panic("not ecdsa private key")
	}

	if err != nil {
		fmt.Println(err)
		return
	}
	//register the maps jwt function
	http.HandleFunc("/maps/jwt", GenerateMapsToken)
	http.Handle("/", http.FileServer(http.Dir("./debug")))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

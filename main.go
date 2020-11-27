package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	//"encoding/json"
	"log"
	"time"

	//...
	// import the jwt-go library
	"github.com/dgrijalva/jwt-go"
	"net/http"

	//...
)

// Create the JWT key used to create the signature
var rawJwtKey []byte
var mapsKey *ecdsa.PrivateKey

var mapsKeyID =  "F8YD4N54KD"
var WORDPRESS_URL = "http://localhost:8000"



type Claims struct {
Issuer string `json:"iss"`
IssuedAt int64 `json:"iat"`
KeyID string `json:"kid"`
Origin string `json:"origin"`
jwt.StandardClaims

}

// Create the Signin handler
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

	var claims Claims
	claims.IssuedAt = time.Now().Unix()
	claims.Issuer = "6G53WHVXA8"

	claims.Origin = site
	claims.ExpiresAt = time.Now().Add(30 * time.Minute).Unix()



	// Get the JSON body and decode into credentials

	//// Declare the expiration time of the token
	//// here, we have kept it as 5 minutes
	//expirationTime := time.Now().Add(5 * time.Minute)
	//// Create the JWT claims, which includes the username and expiry time
	//claims := &Claims{
	//	Username: creds.Username,
	//	StandardClaims: jwt.StandardClaims{
	//		// In JWT, the expiry time is expressed as unix milliseconds
	//		ExpiresAt: expirationTime.Unix(),
	//	},
	//}

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

// Create the Signin handler
//func Signin(w http.ResponseWriter, r *http.Request) {
//var creds Credentials
//// Get the JSON body and decode into credentials
//err := json.NewDecoder(r.Body).Decode(&creds)
//if err != nil {
//// If the structure of the body is wrong, return an HTTP error
//w.WriteHeader(http.StatusBadRequest)
//return
//}
//
//
//
//// Get the expected password from our in memory map
//expectedPassword, ok := users[creds.Username]
//
//// If a password exists for the given user
//// AND, if it is the same as the password we received, the we can move ahead
//// if NOT, then we return an "Unauthorized" status
//if !ok || expectedPassword != creds.Password {
//w.WriteHeader(http.StatusUnauthorized)
//return
//}
//
//// Declare the expiration time of the token
//// here, we have kept it as 5 minutes
//expirationTime := time.Now().Add(5 * time.Minute)
//// Create the JWT claims, which includes the username and expiry time
//claims := &Claims{
//Username: creds.Username,
//StandardClaims: jwt.StandardClaims{
//// In JWT, the expiry time is expressed as unix milliseconds
//ExpiresAt: expirationTime.Unix(),
//},
//}
//
//// Declare the token with the algorithm used for signing, and the claims
//token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//// Create the JWT string
//tokenString, err := token.SignedString(jwtKey)
//if err != nil {
//// If there is an error in creating the JWT return an internal server error
//w.WriteHeader(http.StatusInternalServerError)
//return
//}
//
//// Finally, we set the client cookie for "token" as the JWT we just generated
//// we also set an expiry time which is the same as the token itself
//http.SetCookie(w, &http.Cookie{
//Name:    "token",
//Value:   tokenString,
//Expires: expirationTime,
//})
//}

func main() {
	p8bytes, err := ioutil.ReadFile("AuthKey_F8YD4N54KD.p8")
	if err != nil {
		log.Println(err)
		return
	}

	// Here you need to decode the Apple private key, which is in pem format
	block, _ := pem.Decode(p8bytes)
	// Check if it's a private key
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Println("Failed to decode PEM block containing private key")
		return
	}
	// Get the encoded bytes
	x509Encoded := block.Bytes

	// Now you need an instance of *ecdsa.PrivateKey
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
	// "Signin" and "Welcome" are the handlers that we will implement
	http.HandleFunc("/maps/jwt", GenerateMapsToken)
	http.Handle("/", http.FileServer(http.Dir("./debug")))

	// start the server on port 8000
	//log.Fatal(http.ListenAndServe(":8080", nil))
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraUser "github.com/osallou/goterra-lib/lib/user"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraToken "github.com/osallou/goterra-lib/lib/token"

	terraDeployUtils "github.com/osallou/goterra-deploy/lib"
	// terraDb "github.com/osallou/goterra/lib/db"
)

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection
var nsCollection *mongo.Collection
var recipeCollection *mongo.Collection
var appCollection *mongo.Collection
var endpointCollection *mongo.Collection
var runCollection *mongo.Collection

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Claims contains JWT claims
/*
type Claims struct {
	UID        string          `json:"uid"`
	APIKey     string          `json:"apikey"`
	Email      string          `json:"email"`
	Admin      bool            `json:"admin"`
	Namespaces map[string]bool `json:"namespaces"`
	jwt.StandardClaims
}*/

// Recipe describe a recipe for an app
type Recipe struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Script       string             `json:"script"`
	Public       bool               `json:"public"`
	Namespace    string             `json:"namespace"`
	BaseImages   []string           `json:"base"`
	ParentRecipe string             `json:"parent"`
	Timestamp    int64              `json:"ts"`
	Previous     string             `json:"prev"`   // Previous recipe id, for versioning
	Inputs       map[string]string  `json:"inputs"` // List of input variables needed when executing at app for this recipe, those variables should be sent as env_XX if XX is in requires: varname,label
	Tags         []string           `json:"tags"`
}

// Application descripe an app to deploy
type Application struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Public       bool               `json:"public"`
	Recipes      []string           `json:"recipes"`
	Namespace    string             `json:"namespace"`
	Templates    map[string]string  `json:"templates"` // One template per endpoint type (openstack, ...)
	Inputs       map[string]string  `json:"inputs"`    // expected inputs varname, label
	SecretInputs map[string]string  `json:"secrets"`   // Secret variables (password, etc.) will be given to terraform as env variables
	Image        string             `json:"image"`
	Timestamp    int64              `json:"ts"`
	Previous     string             `json:"prev"` // Previous app id, for versioning
}

// Run represents a deployment info for an app
type Run struct {
	ID         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	AppID      string             `json:"appID"` // Application id
	Inputs     map[string]string  `json:"inputs"`
	Status     string             `json:"status"`
	Endpoint   string             `json:"endpoint"`
	Namespace  string             `json:"namespace"`
	UID        string
	Start      int64         `json:"start"`
	Duration   time.Duration `json:"duration"`
	Outputs    string        `json:"outputs"`
	Deployment string        `json:"deployment"`
}

const (
	openstack = "openstack"
	// amazon    = "amazon"
	// azure     = "azure"
)

// Openstack maps to openstack provider in openstack
type Openstack struct {
	UserName          string `json:"user_name"`
	Password          string `json:"password"`
	Flavor            string `json:"flavor_name"`
	KeyPair           string `json:"key_pair"`
	TenantName        string `json:"tenant_name"`
	TenantID          string `json:"tenant_id"`
	AuthURL           string `json:"auth_url"`
	Region            string `json:"region"`
	DomainName        string `json:"domain_name,omitempty"`
	DomainID          string `json:"domain_id,omitempty"`
	ProjectDomainID   string `json:"project_domain_id,omitempty"`
	ProjectDomainName string `json:"project_domain_name,omitempty"`
	UserDomainID      string `json:"user_domain_id,omitempty"`
	UserDomainName    string `json:"user_domain_name,omitempty"`

	Inputs map[string]string `json:"inputs"` // expected inputs (credentials, ...), varname, label
}

// EndPoint specifies a cloud endpoint data
type EndPoint struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name      string             `json:"name"`
	Kind      string             `json:"kind"` // openstack, etc.
	Namespace string             `json:"namespace"`
	// Openstack Openstack          `json:"openstack"` // for Kind=openstack
	Features map[string]string `json:"features"`
	Inputs   map[string]string `json:"inputs"` // expected inputs varname, label
	Config   map[string]string `json:"config"` // Preset some inputs like endpoints url, ... to be set in terraform variables
	Images   map[string]string `json:"images"` // map recipe image id to endpoint image id
}

// CheckAPIKey check X-API-Key authorization content and returns user info
func CheckAPIKey(apiKey string) (data terraUser.AuthData, err error) {
	err = nil
	data = terraUser.AuthData{}
	if apiKey == "" {
		err = errors.New("missing X-API-Key")
	} else {
		var tauthErr error
		data, tauthErr = terraUser.Check(apiKey)
		if tauthErr != nil {
			err = errors.New("invalid api key")
		} else {
			data.User.Logged = true
		}
	}
	log.Printf("[DEBUG] User logged: %s", data.User.UID)
	return data, err
}

// CheckToken checks Fernet token
func CheckToken(authToken string) (user terraUser.User, err error) {
	// config := terraConfig.LoadConfig()

	tokenStr := strings.Replace(authToken, "Bearer", "", -1)
	tokenStr = strings.TrimSpace(tokenStr)

	msg, errMsg := terraToken.FernetDecode([]byte(tokenStr))
	if errMsg != nil {
		return user, errMsg
	}
	json.Unmarshal(msg, &user)
	return user, nil
	/*
		data, err := base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			fmt.Printf("Token error: %v\n", err)
			return claims, errors.New("Invalid token")
		}
		decodedToken := string(decrypt(data, config.Secret))

		claims = &Claims{}
		token, err := jwt.ParseWithClaims(decodedToken, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.Secret), nil
		})
		if err != nil || !token.Valid || claims.Audience != "goterra/deploy" {
			fmt.Printf("Token error: %v\n", err)
			return claims, errors.New("Invalid token")
		}
		fmt.Printf("DEBUG %+v\n", claims)
		return claims, nil
	*/
}

// encrypt and decrypt
/*
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}
*/

// end of encrypt

// createToken creates a JWT token for input user
/*
func createToken(user terraUser.User) (tokenString string, err error) {
	config := terraConfig.LoadConfig()
	mySigningKey := []byte(config.Secret)

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UID:        user.UID,
		APIKey:     user.APIKey,
		Admin:      user.Admin,
		Namespaces: make(map[string]bool),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Audience:  "goterra/deploy",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(mySigningKey)

	tokenBytes := []byte(tokenString)
	tokenString = base64.StdEncoding.EncodeToString(encrypt(tokenBytes, config.Secret))
	return tokenString, err
}
*/

// BindHandler gets API Key and returns a Token
var BindHandler = func(w http.ResponseWriter, r *http.Request) {
	data, err := CheckAPIKey(r.Header.Get("X-API-Key"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	resp := map[string]interface{}{"token": data.Token}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CreateNSHandler creates a new namespace
var CreateNSHandler = func(w http.ResponseWriter, r *http.Request) {
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraDeployUtils.NSData{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"name": data.Name,
	}
	var nsdb terraDeployUtils.NSData
	err = nsCollection.FindOne(ctx, ns).Decode(&nsdb)
	if err != mongo.ErrNoDocuments {
		// already exists
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "namespace already exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	ns = bson.M{
		"name":    data.Name,
		"owners":  []string{claims.UID},
		"members": make([]string, 0),
	}

	newns, err := nsCollection.InsertOne(ctx, ns)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to create namespace"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := map[string]interface{}{"ns": newns.InsertedID}
	w.Header().Add("Content-Type", "application/json")
	config := terraConfig.LoadConfig()
	remote := []string{config.URL, "deploy", "ns", newns.InsertedID.(primitive.ObjectID).Hex()}
	w.Header().Add("Location", strings.Join(remote, "/"))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// UpdateNSHandler updates namespace info
var UpdateNSHandler = func(w http.ResponseWriter, r *http.Request) {
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	vars := mux.Vars(r)
	nsID := vars["id"]

	data := &terraDeployUtils.NSData{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	objID, _ := primitive.ObjectIDFromHex(nsID)
	ns := bson.M{
		"_id": objID,
	}

	var nsdb terraDeployUtils.NSData
	err = nsCollection.FindOne(ctx, ns).Decode(&nsdb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "namespace does not exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	isOwner := false
	for _, owner := range nsdb.Owners {
		if owner == claims.UID {
			isOwner = true
			break
		}
	}
	if !isOwner && claims.Admin == false {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not namespace owner"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	newns := bson.M{
		"_id":     objID,
		"name":    data.Name,
		"owners":  data.Owners,
		"members": data.Members,
	}

	err = nsCollection.FindOneAndReplace(ctx, ns, newns).Decode(&nsdb)
	if err != nil {
		log.Printf("[ERROR] faild to update namespace %v", err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to update namespace"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := map[string]interface{}{"ns": nsID}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSHandler updates namespace info
var GetNSHandler = func(w http.ResponseWriter, r *http.Request) {
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	vars := mux.Vars(r)
	nsID := vars["id"]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	objID, _ := primitive.ObjectIDFromHex(nsID)
	ns := bson.M{
		"_id": objID,
	}

	var nsdb terraDeployUtils.NSData
	err = nsCollection.FindOne(ctx, ns).Decode(&nsdb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "namespace does not exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	isOwner := false
	for _, owner := range nsdb.Owners {
		if owner == claims.UID {
			isOwner = true
			break
		}
	}
	if !isOwner && claims.Admin == false {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not namespace owner"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := map[string]interface{}{"ns": nsdb}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSALLHandler list namespaces
var GetNSALLHandler = func(w http.ResponseWriter, r *http.Request) {
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	var ns map[string]interface{}
	if claims.Admin {
		keys, ok := r.URL.Query()["all"]
		if ok && keys[0] == "1" {
			ns = bson.M{}
		} else {
			ns = bson.M{
				"$or": []interface{}{
					bson.M{"owners": claims.UID},
					bson.M{"members": claims.UID},
				},
			}
		}
	} else {
		ns = bson.M{
			"$or": []interface{}{
				bson.M{"owners": claims.UID},
				bson.M{"members": claims.UID},
			},
		}
	}

	/*
		if !claims.Admin {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not admin"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	*/

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namespaces := make([]terraDeployUtils.NSData, 0)
	nscursor, _ := nsCollection.Find(ctx, ns)
	for nscursor.Next(ctx) {
		var nsdb terraDeployUtils.NSData
		nscursor.Decode(&nsdb)
		namespaces = append(namespaces, nsdb)
	}

	resp := map[string]interface{}{"ns": namespaces}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CreateNSRecipeHandler creates a new recipe for namespace
var CreateNSRecipeHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &Recipe{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	t := time.Now()
	data.Timestamp = t.Unix()
	data.Namespace = nsID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"name":      data.Name,
		"namespace": data.Namespace,
	}
	var recipedb Recipe
	err = recipeCollection.FindOne(ctx, ns).Decode(&recipedb)
	if err != mongo.ErrNoDocuments {
		// already exists
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "recipe already exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	newrecipe, err := recipeCollection.InsertOne(ctx, data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to create recipe"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	config := terraConfig.LoadConfig()
	remote := []string{config.URL, "deploy", "ns", nsID, "recipe", newrecipe.InsertedID.(primitive.ObjectID).Hex()}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Location", strings.Join(remote, "/"))
	w.WriteHeader(http.StatusCreated)

	resp := map[string]interface{}{"recipe": newrecipe.InsertedID}

	json.NewEncoder(w).Encode(resp)
}

// GetNSRecipesHandler get namespace recipes
var GetNSRecipesHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
	}

	recipes := make([]Recipe, 0)
	cursor, err := recipeCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var recipedb Recipe
		cursor.Decode(&recipedb)
		recipes = append(recipes, recipedb)
	}

	resp := map[string]interface{}{"recipes": recipes}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSRecipeHandler get namespace recipe
var GetNSRecipeHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	recipeID, _ := primitive.ObjectIDFromHex(vars["recipe"])
	claims, claimserr := CheckToken(r.Header.Get("Authorization"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
		"_id":       recipeID,
	}

	var recipedb Recipe
	err := recipeCollection.FindOne(ctx, ns).Decode(&recipedb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "recipe not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	if !recipedb.Public {
		if claimserr != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", claimserr)}
			json.NewEncoder(w).Encode(respError)
			return
		}
		if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	resp := map[string]interface{}{"recipe": recipedb}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CreateNSAppHandler creates a new application for namespace
var CreateNSAppHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &Application{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	t := time.Now()
	data.Timestamp = t.Unix()
	data.Namespace = nsID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"name":      data.Name,
		"namespace": data.Namespace,
	}
	var appdb Application
	err = appCollection.FindOne(ctx, ns).Decode(&appdb)
	if err != mongo.ErrNoDocuments {
		// already exists
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "application already exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	baseImage := ""
	possibleBaseImagesNew := true
	possibleBaseImagesSet := make(map[string]bool, 0)
	possibleBaseImages := make([]string, 0)

	for _, rec := range data.Recipes {
		parentBaseImages, parentErr := checkRecipeImage(rec, data.Namespace)
		if parentErr != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": parentErr.Error()}
			json.NewEncoder(w).Encode(respError)
			return
		}

		gotACommonBaseImage := false
		// populating for first recipe
		if possibleBaseImagesNew {
			gotACommonBaseImage = true
			possibleBaseImages = append(possibleBaseImages, parentBaseImages...)
			for _, availableImage := range parentBaseImages {
				possibleBaseImagesNew = false
				possibleBaseImagesSet[availableImage] = true
			}
		} else {
			possibleBaseImagesNew = false
			for _, availableImage := range parentBaseImages {
				if _, ok := possibleBaseImagesSet[availableImage]; ok {
					possibleBaseImages = append(possibleBaseImages, availableImage)
					gotACommonBaseImage = true
				}
			}
		}

		if !gotACommonBaseImage {
			// No common base image in recipes
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": fmt.Sprintf("recipes using different base images")}
			json.NewEncoder(w).Encode(respError)
			return
		}

	}

	// We may have multiple common base image for recipes, take first
	baseImage = possibleBaseImages[0]

	if baseImage == "" {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "could not find a base image in recipes"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	data.Image = baseImage

	newapp, err := appCollection.InsertOne(ctx, data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to create application"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	config := terraConfig.LoadConfig()
	remote := []string{config.URL, "deploy", "ns", nsID, "app", newapp.InsertedID.(primitive.ObjectID).Hex()}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Location", strings.Join(remote, "/"))
	w.WriteHeader(http.StatusCreated)

	resp := map[string]interface{}{"app": newapp.InsertedID}

	json.NewEncoder(w).Encode(resp)
}

// checkRecipeImage checks (sub)recipe exists, and is public or authorized, returns base image of recipe
func checkRecipeImage(recipe string, ns string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recipeID, _ := primitive.ObjectIDFromHex(recipe)
	recfilter := bson.M{
		"_id": recipeID,
	}
	var recdb Recipe
	recerr := recipeCollection.FindOne(ctx, recfilter).Decode(&recdb)
	if recerr == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("no recipe found %s", recipe)
	}
	if !recdb.Public && recdb.Namespace != ns {
		return nil, fmt.Errorf("recipe is not public or in namespace %s", recipe)
	}
	if recdb.ParentRecipe != "" {
		parentImage, err := checkRecipeImage(recdb.ParentRecipe, ns)
		if err != nil {
			return nil, err
		}
		return parentImage, nil
	}
	if recdb.BaseImages == nil || len(recdb.BaseImages) == 0 {
		return nil, fmt.Errorf("recipe has no base image nor parent recipe")
	}
	return recdb.BaseImages, nil

}

// GetNSAppsHandler get namespace apps
var GetNSAppsHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
	}

	apps := make([]Application, 0)
	cursor, err := appCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var appdb Application
		cursor.Decode(&appdb)
		apps = append(apps, appdb)
	}

	resp := map[string]interface{}{"apps": apps}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSAppHandler get namespace application
var GetNSAppHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	appID, _ := primitive.ObjectIDFromHex(vars["application"])
	claims, claimserr := CheckToken(r.Header.Get("Authorization"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
		"_id":       appID,
	}

	var appdb Application
	err := appCollection.FindOne(ctx, ns).Decode(&appdb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "application not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	if !appdb.Public {
		if claimserr != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", claimserr)}
			json.NewEncoder(w).Encode(respError)
			return
		}
		if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	resp := map[string]interface{}{"app": appdb}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// AppExpectedInputs gets all inputs from app, recipes and defined endpoints
type AppExpectedInputs struct {
	Application map[string]string            `json:"application"`
	Recipes     map[string]string            `json:"recipes"`
	EndPoints   map[string]map[string]string `json:"endpoints"`
}

// getRecipeInputs get (sub)recipe inputs
func getRecipeInputs(recipe string, ns string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recipeID, _ := primitive.ObjectIDFromHex(recipe)
	recfilter := bson.M{
		"_id": recipeID,
	}
	var recdb Recipe
	recerr := recipeCollection.FindOne(ctx, recfilter).Decode(&recdb)
	if recerr == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("no recipe found %s", recipe)
	}
	if !recdb.Public && recdb.Namespace != ns {
		return nil, fmt.Errorf("recipe is not public or in namespace %s", recipe)
	}
	if recdb.ParentRecipe != "" {
		parentInputs, err := getRecipeInputs(recdb.ParentRecipe, ns)
		if err != nil {
			return nil, err
		}
		for k, v := range parentInputs {
			recdb.Inputs[k] = v
		}
		return recdb.Inputs, nil
	}
	if recdb.BaseImages == nil || len(recdb.BaseImages) == 0 {
		return nil, fmt.Errorf("recipe has no base image nor parent recipe")
	}
	return recdb.Inputs, nil

}

//GetNSAppInputsHandler gets application expected inputs for a run
var GetNSAppInputsHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	appID, _ := primitive.ObjectIDFromHex(vars["application"])
	claims, claimserr := CheckToken(r.Header.Get("Authorization"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
		"_id":       appID,
	}

	var appdb Application
	err := appCollection.FindOne(ctx, ns).Decode(&appdb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "application not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	if !appdb.Public {
		if claimserr != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", claimserr)}
			json.NewEncoder(w).Encode(respError)
			return
		}
		if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	appInputs := &AppExpectedInputs{}
	appInputs.Application = appdb.Inputs
	// Get recipes
	appInputs.Recipes = make(map[string]string)
	for _, recipe := range appdb.Recipes {
		elts, eltserr := getRecipeInputs(recipe, nsID)
		if eltserr == nil && elts != nil {
			for eltsk, eltsv := range elts {
				appInputs.Recipes[eltsk] = eltsv
			}
		}
	}

	// Get endpoints
	epns := bson.M{
		"namespace": nsID,
	}

	appInputs.EndPoints = make(map[string]map[string]string)
	// endpoints := make([]EndPoint, 0)
	cursor, err := endpointCollection.Find(ctx, epns)
	for cursor.Next(ctx) {
		var endpointdb EndPoint
		cursor.Decode(&endpointdb)
		appInputs.EndPoints[endpointdb.Name] = endpointdb.Inputs
		/*
			appInputs.EndPoints["openstack"] = endpointdb.Inputs
			for k, v := range endpointdb.Openstack.Inputs {
				appInputs.EndPoints["openstack"][k] = v
			}

			endpoints = append(endpoints, endpointdb)
		*/
	}

	resp := map[string]interface{}{"app": appInputs}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Endpoints *************************************

// CreateNSEndpointHandler creates a new endpoint for namespace
var CreateNSEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &EndPoint{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	data.Namespace = nsID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"name":      data.Name,
		"namespace": data.Namespace,
	}
	var endpointdb EndPoint
	err = endpointCollection.FindOne(ctx, ns).Decode(&endpointdb)
	if err != mongo.ErrNoDocuments {
		// already exists
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "endpoint already exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	newendpoint, err := endpointCollection.InsertOne(ctx, data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to create endpoint"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	config := terraConfig.LoadConfig()
	remote := []string{config.URL, "deploy", "ns", nsID, "endpoint", newendpoint.InsertedID.(primitive.ObjectID).Hex()}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Location", strings.Join(remote, "/"))
	w.WriteHeader(http.StatusCreated)

	resp := map[string]interface{}{"endpoint": newendpoint.InsertedID}

	json.NewEncoder(w).Encode(resp)
}

// GetNSEndpointsHandler get namespace endpoints
var GetNSEndpointsHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
	}

	endpoints := make([]EndPoint, 0)
	cursor, err := endpointCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var endpointdb EndPoint
		cursor.Decode(&endpointdb)
		endpoints = append(endpoints, endpointdb)
	}

	resp := map[string]interface{}{"endpoints": endpoints}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSEndpointHandler get namespace endpoint
var GetNSEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	endpointID, _ := primitive.ObjectIDFromHex(vars["endpoint"])
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"namespace": nsID,
		"_id":       endpointID,
	}

	var endpointdb EndPoint
	err = endpointCollection.FindOne(ctx, ns).Decode(&endpointdb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "endpoint not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := map[string]interface{}{"endpoint": endpointdb}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// End of Endpoints ******************************

// Run *******************************************

func getTerraTemplates(userID string, nsID string, app string, run *Run) (variablesTf string, appTf string, err error) {
	appID, _ := primitive.ObjectIDFromHex(app)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"_id": appID,
	}

	var appDb Application
	err = appCollection.FindOne(ctx, ns).Decode(&appDb)
	if err == mongo.ErrNoDocuments {
		return "", "", fmt.Errorf("application not found")
	}
	if !appDb.Public && !terraDeployUtils.IsMemberOfNS(nsCollection, appDb.Namespace, userID) {
		return "", "", fmt.Errorf("not allowed to access namespace %s by %s", appDb.Namespace, userID)
	}

	endpointID, _ := primitive.ObjectIDFromHex(run.Endpoint)
	ns = bson.M{
		"namespace": nsID,
		"_id":       endpointID,
	}
	var endpointDb EndPoint
	err = endpointCollection.FindOne(ctx, ns).Decode(&endpointDb)
	if err == mongo.ErrNoDocuments {
		return "", "", fmt.Errorf("endpoint not found")
	}

	appTf = appDb.Templates[endpointDb.Kind]
	if appTf == "" {
		return "", "", fmt.Errorf("no " + endpointDb.Kind + " template found")
	}

	variablesTf = ""
	loadedVariables := make(map[string]bool)

	// Run
	for key := range run.Inputs {
		variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", key, run.Inputs[key])
		loadedVariables[key] = true
	}

	imageID := appDb.Image
	if val, ok := endpointDb.Images[appDb.Image]; ok {
		imageID = val
	}

	if _, ok := loadedVariables["image_id"]; !ok {
		variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "image_id", imageID)
	}

	// Endpoint
	if terraDeployUtils.IsMemberOfNS(nsCollection, nsID, userID) {
		for key := range endpointDb.Config {
			variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", key, endpointDb.Config[key])
		}
	}

	for key := range endpointDb.Features {
		variablesTf += fmt.Sprintf("variable feature_%s {\n    default=\"%s\"\n}\n", key, endpointDb.Features[key])
	}

	config := terraConfig.LoadConfig()

	// General
	if _, ok := loadedVariables["got_url"]; !ok {
		variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "goterra_url", config.URL)
	}

	variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "goterra_application", app)
	variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "goterra_namespace", nsID)

	return variablesTf, appTf, nil
}

// CreateRunTerraformHandlerHandler get terraform templates to exec app but does not deploy it
var CreateRunTerraformHandlerHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]

	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	/*
		if !claims.Admin && !terraDeployUtils.IsMemberOfNS(nsCollection, nsID, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	*/

	run := &Run{}
	err = json.NewDecoder(r.Body).Decode(run)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	variablesTf, appTf, errTf := getTerraTemplates(claims.UID, nsID, vars["application"], run)
	if errTf != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": errTf.Error()}
		json.NewEncoder(w).Encode(respError)
		return
	}

	// Add api key
	variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "goterra_apikey", "")

	resp := map[string]interface{}{"variables.tf": variablesTf, "app.tf": appTf}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CreateRunHandler generates terraform setup and ask for execution
var CreateRunHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]

	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	run := &Run{}
	err = json.NewDecoder(r.Body).Decode(run)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	variablesTf, appTf, errTf := getTerraTemplates(claims.UID, nsID, vars["application"], run)
	if errTf != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": errTf.Error()}
		json.NewEncoder(w).Encode(respError)
		return
	}

	// Add api key
	variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "goterra_apikey", claims.APIKey)

	config := terraConfig.LoadConfig()
	run.AppID = vars["application"]
	run.UID = claims.UID
	run.Namespace = nsID
	run.Start = time.Now().Unix()
	run.Status = "pending"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	newrun, err := runCollection.InsertOne(ctx, run)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to create run"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	runPathElts := []string{config.Deploy.Path, newrun.InsertedID.(primitive.ObjectID).Hex()}
	runPath := strings.Join(runPathElts, "/")
	os.MkdirAll(runPath, os.ModePerm)
	errFile := ioutil.WriteFile(runPath+"/variables.tf", []byte(variablesTf), 0644)
	if errFile != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to write variables.tf"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	errAppFile := ioutil.WriteFile(runPath+"/app.tf", []byte(appTf), 0644)
	if errAppFile != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to write app.tf"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	amqpErr := terraDeployUtils.SendRunAction("deploy", newrun.InsertedID.(primitive.ObjectID).Hex())
	if amqpErr != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": fmt.Sprintf("failed to deploy:%s", amqpErr)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := map[string]interface{}{"run": newrun.InsertedID}
	w.Header().Add("Content-Type", "application/json")
	remote := []string{config.URL, "deploy", "ns", nsID, "run", newrun.InsertedID.(primitive.ObjectID).Hex()}
	w.Header().Add("Location", strings.Join(remote, "/"))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// End of Run ************************************

func main() {

	config := terraConfig.LoadConfig()

	consulErr := terraConfig.ConsulDeclare("got-deploy", "/deploy")
	if consulErr != nil {
		fmt.Printf("Failed to register: %s", consulErr.Error())
		panic(consulErr)
	}

	mongoClient, err := mongo.NewClient(mongoOptions.Client().ApplyURI(config.Mongo.URL))
	if err != nil {
		log.Printf("[ERROR] Failed to connect to mongo server %s\n", config.Mongo.URL)
		os.Exit(1)
	}
	ctx, cancelMongo := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelMongo()

	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to mongo server %s\n", config.Mongo.URL)
		os.Exit(1)
	}
	nsCollection = mongoClient.Database(config.Mongo.DB).Collection("ns")
	recipeCollection = mongoClient.Database(config.Mongo.DB).Collection("recipe")
	appCollection = mongoClient.Database(config.Mongo.DB).Collection("application")
	endpointCollection = mongoClient.Database(config.Mongo.DB).Collection("endpoint")
	runCollection = mongoClient.Database(config.Mongo.DB).Collection("run")

	// userCollection = mongoClient.Database(config.Mongo.DB).Collection("users")

	r := mux.NewRouter()
	r.HandleFunc("/deploy", HomeHandler).Methods("GET")
	r.HandleFunc("/deploy/session/bind", BindHandler).Methods("POST")
	r.HandleFunc("/deploy/ns", GetNSALLHandler).Methods("GET")      // admin only, get namespaces
	r.HandleFunc("/deploy/ns", CreateNSHandler).Methods("POST")     // create a namespace, user becomes owner
	r.HandleFunc("/deploy/ns/{id}", UpdateNSHandler).Methods("PUT") // update name, owners and members
	r.HandleFunc("/deploy/ns/{id}", GetNSHandler).Methods("GET")    // get owners and members
	// 	r.HandleFunc("/deploy/ns/{id}", DeleteNSHandler).Methods("DELETE")             // Delete namespace

	r.HandleFunc("/deploy/ns/{id}/recipe", CreateNSRecipeHandler).Methods("POST")      // create recipe
	r.HandleFunc("/deploy/ns/{id}/recipe", GetNSRecipesHandler).Methods("GET")         // get recipes
	r.HandleFunc("/deploy/ns/{id}/recipe/{recipe}", GetNSRecipeHandler).Methods("GET") // get recipe
	// r.HandleFunc("/deploy/ns/{id}/recipe/{recipe}", UpdateNSRecipeHandler).Methods("PUT") // update recipe
	// r.HandleFunc("/deploy/ns/{id}/recipe/{recipe}", DeleteNSRecipeHandler).Methods("DELETE")  // delete recipe

	r.HandleFunc("/deploy/ns/{id}/app", CreateNSAppHandler).Methods("POST") // create app
	r.HandleFunc("/deploy/ns/{id}/app", GetNSAppsHandler).Methods("GET")    // get namespace apps
	// r.HandleFunc("/deploy/ns/{id}/app/{application}", UpdateNSAppHandler).Methods("PUT")  // update app
	r.HandleFunc("/deploy/ns/{id}/app/{application}", GetNSAppHandler).Methods("GET")              //get app
	r.HandleFunc("/deploy/ns/{id}/app/{application}/inputs", GetNSAppInputsHandler).Methods("GET") //get app input requirements

	// r.HandleFunc("/deploy/ns/{id}/app/{application}", GetNSAppHandler).Methods("DELETE")  //delete app

	// r.HandleFunc("/deploy/recipe", GetPublicRecipesHandler).Methods("GET")  //get public recipes
	// r.HandleFunc("/deploy/app", GetPublicAppsHandler).Methods("GET")  //get public apps

	r.HandleFunc("/deploy/ns/{id}/run/{application}", CreateRunHandler).Methods("POST") // deploy app
	// r.HandleFunc("/deploy/ns/{id}/run/{run}", GetRunHandler).Methods("GET")  // get run info
	r.HandleFunc("/deploy/ns/{id}/run/{application}/terraform", CreateRunTerraformHandlerHandler).Methods("POST") //get terraform templates for a run but do not deploy app

	// r.HandleFunc("/deploy/ns/{id}/run/{run}", DeleteRunHandler).Methods("DELETE")  // stop run

	r.HandleFunc("/deploy/ns/{id}/endpoint", GetNSEndpointsHandler).Methods("GET")           // get ns endpoints
	r.HandleFunc("/deploy/ns/{id}/endpoint", CreateNSEndpointHandler).Methods("POST")        // add endpoint
	r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}", GetNSEndpointHandler).Methods("GET") // get endpoint
	// r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}", DeleteNSEndpointHandler).Methods("DELETE")  // delete endpoint

	handler := cors.Default().Handler(r)

	loggedRouter := handlers.LoggingHandler(os.Stdout, handler)

	srv := &http.Server{
		Handler: loggedRouter,
		Addr:    fmt.Sprintf("%s:%d", config.Web.Listen, config.Web.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())

}

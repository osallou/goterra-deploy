package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraUser "github.com/osallou/goterra-lib/lib/user"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraDeployUtils "github.com/osallou/goterra-deploy/lib"
)

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection
var nsCollection *mongo.Collection
var recipeCollection *mongo.Collection

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Claims contains JWT claims
type Claims struct {
	UID        string          `json:"uid"`
	Email      string          `json:"email"`
	Admin      bool            `json:"admin"`
	Namespaces map[string]bool `json:"namespaces"`
	jwt.StandardClaims
}

// Recipe describe a recipe for an app
type Recipe struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Script       string             `json:"script"`
	Public       bool               `json:"public"`
	Namespace    string             `json:"namespace"`
	BaseImage    string             `json:"base"`
	ParentRecipe string             `json:"parent"`
}

// Application descripe an app to deploy
type Application struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Public      bool               `json:"public"`
	Recipes     []string           `json:"recipes"`
	Namespace   string             `json:"namespace"`
}

// TerraDeploy represents a deployment info for an app
type TerraDeploy struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	AppID        string             // Application id
	Requirements map[string]interface{}
	Credentials  map[string]interface{}
}

const (
	openstack = "openstack"
)

// EndPoint specifies a cloud endpoint data
type EndPoint struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name      string
	Type      string // openstack, etc.
	Namespace string
	Info      map[string]interface{}
}

// CheckAPIKey check X-API-Key authorization content and returns user info
func CheckAPIKey(apiKey string) (checkedUser terraUser.User, err error) {
	err = nil
	user := terraUser.User{}
	if apiKey == "" {
		err = errors.New("missing X-API-Key")
	} else {
		var tauthErr error
		user, tauthErr = terraUser.Check(apiKey)
		fmt.Printf("in checkapikey %+v\n", user)

		if tauthErr != nil {
			err = errors.New("invalid api key")
		} else {
			user.Logged = true
		}
	}
	log.Printf("[DEBUG] User logged: %s", user.UID)
	return user, err
}

// CheckToken checks JWT token
func CheckToken(authToken string) (claims *Claims, err error) {
	config := terraConfig.LoadConfig()

	tokenStr := strings.Replace(authToken, "Bearer", "", -1)
	tokenStr = strings.TrimSpace(tokenStr)
	claims = &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Secret), nil
	})
	if err != nil || !token.Valid || claims.Audience != "goterra/deploy" {
		fmt.Printf("Token error: %v\n", err)
		return claims, errors.New("Invalid token")
	}

	return claims, nil
}

// createToken creates a JWT token for input user
func createToken(user terraUser.User) (tokenString string, err error) {
	config := terraConfig.LoadConfig()
	mySigningKey := []byte(config.Secret)

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UID:        user.UID,
		Admin:      user.Admin,
		Namespaces: make(map[string]bool),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Audience:  "goterra/deploy",
		},
	}
	// TODO Find namespaces for user (owner or member) and set namespaces
	// Or update user with additional info ? not the best, should be independent from user "login" info/service
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(mySigningKey)
	return tokenString, err
}

// BindHandler gets API Key and returns a JWT Token
var BindHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckAPIKey(r.Header.Get("X-API-Key"))
	fmt.Printf("after checkapikey %+v", user)

	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	token, err := createToken(user)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		respError := map[string]interface{}{"message": "failed to create token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	resp := map[string]interface{}{"token": token}
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

	if !claims.Admin {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not admin"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{}

	var nsdb terraDeployUtils.NSData
	namespaces := make([]terraDeployUtils.NSData, 0)
	nscursor, _ := nsCollection.Find(ctx, ns)
	for nscursor.Next(ctx) {
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
	data.Namespace = nsID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"name": data.Name,
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
	var recipedb Recipe
	cursor, err := recipeCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		cursor.Decode(&recipedb)
		recipes = append(recipes, recipedb)
		fmt.Printf("? %+v\n", recipedb)
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
		"_id":       recipeID,
	}

	var recipedb Recipe
	err = recipeCollection.FindOne(ctx, ns).Decode(&recipedb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "recipe not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := map[string]interface{}{"recipe": recipedb}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {

	config := terraConfig.LoadConfig()
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

	// r.HandleFunc("/deploy/ns/{id}/app", CreateNSAppHandler).Methods("POST")  // create app
	// r.HandleFunc("/deploy/ns/{id}/app", GetNSAppsHandler).Methods("GET")  // get namespace apps
	// r.HandleFunc("/deploy/ns/{id}/app/{application}", UpdateNSAppHandler).Methods("PUT")  // update app
	// r.HandleFunc("/deploy/ns/{id}/app/{application}", GetNSAppHandler).Methods("GET")  //get app
	// r.HandleFunc("/deploy/ns/{id}/app/{application}", GetNSAppHandler).Methods("DELETE")  //delete app

	// r.HandleFunc("/deploy/recipe", GetPublicRecipesHandler).Methods("GET")  //get public recipes
	// r.HandleFunc("/deploy/app", GetPublicAppsHandler).Methods("GET")  //get public apps
	// r.HandleFunc("/deploy/ns/{id}/run/{application}", CreateRunHandler).Methods("POST")  // deploy app
	// r.HandleFunc("/deploy/ns/{id}/run/{run}", GetRunHandler).Methods("GET")  // get run info
	// r.HandleFunc("/deploy/ns/{id}/run/{run}", DeleteRunHandler).Methods("DELETE")  // stop run

	// r.HandleFunc("/deploy/ns/{id}/endpoint", CreateNSEndpointsHandler).Methods("GET")  // get ns endpoints
	// r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}", CreateNSEndpointHandler).Methods("POST")  // add endpoint
	// r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}", GetNSEndpointHandler).Methods("GET")  // get endpoint
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

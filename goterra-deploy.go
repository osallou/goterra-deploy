package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
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

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	terraToken "github.com/osallou/goterra-lib/lib/token"
	// terraDeployUtils "github.com/osallou/goterra-deploy/lib"
	// terraDb "github.com/osallou/goterra/lib/db"
	terraModel "github.com/osallou/goterra-lib/lib/model"
)

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection
var nsCollection *mongo.Collection
var recipeCollection *mongo.Collection
var appCollection *mongo.Collection
var endpointCollection *mongo.Collection
var endpointSecretCollection *mongo.Collection
var runCollection *mongo.Collection
var templateCollection *mongo.Collection

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

/*
// Model defines a set of VM which can be used to generate some terraform templates for openstack, ...
type Model struct {
	Name             string `json:"name"`
	Count            int64  `json:"count"`
	PublicIP         string `json:"public_ip"`
	EphemeralStorage string `json:"ephemeral_disk"`
	SharedStorage    string `json:"shared_storage"`
}

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

	// 	Remote      string             `json:"remote"` // path in git repo
	// 	RemoteVersion      string             `json:"rversion"`
	// 	Version      unit64             `json:"version"` //

}

// Template represents a terraform template
type Template struct {
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Namespace     string             `json:"namespace"`
	Timestamp     int64              `json:"ts"`
	Public        bool               `json:"public"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Data          map[string]string  `json:"data"`     // map of cloud kind / terraform template
	Inputs        map[string]string  `json:"inputs"`   // expected inputs varname, label
	Remote        string             `json:"remote"`   // name of template in repo (dir)
	RemoteVersion uint64             `json:"rversion"` // version of template in repo (subdir)
	Version       uint64             `json:"version"`
	Previous      string             `json:"prev"` // Previous recipe id, for versioning
	Tags          []string           `json:"tags"`
}

// Application descripe an app to deploy
type Application struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Public      bool               `json:"public"`
	Recipes     []string           `json:"recipes"`
	Namespace   string             `json:"namespace"`
	Templates   map[string]string  `json:"templates"` // One template per endpoint type (openstack, ...)
	Model       []Model            `json:"model"`     // Model describe expected VM, templates will be generated from model
	Inputs      map[string]string  `json:"inputs"`    // expected inputs varname, label
	Image       string             `json:"image"`
	Timestamp   int64              `json:"ts"`
	Previous    string             `json:"prev"` // Previous app id, for versioning
}

// Event represent an action (deploy, destroy, etc.) on a run (historical data)
type Event struct {
	TS      int64  `json:"ts"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
}

// Run represents a deployment info for an app
type Run struct {
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	ID              primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	AppID           string             `json:"appID"` // Application id
	Inputs          map[string]string  `json:"inputs"`
	SensitiveInputs map[string]string  `json:"secretinputs"` // Secret variables (password, etc.) will be given to terraform as env variables
	Status          string             `json:"status"`
	Endpoint        string             `json:"endpoint"`
	Namespace       string             `json:"namespace"`
	UID             string
	Start           int64   `json:"start"`
	End             int64   `json:"end"`
	Duration        float64 `json:"duration"`
	Outputs         string  `json:"outputs"`
	Error           string  `json:"error"`
	Deployment      string  `json:"deployment"`
	Events          []Event `json:"events"`
}
*/

const (
	openstack = "openstack"
	// amazon    = "amazon"
	// azure     = "azure"
)

/*
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
*/

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
	log.Debug().Str("uid", data.User.UID).Msg("User logged")
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
}

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
	config := terraConfig.LoadConfig()
	if !config.ACL.AllowUserCreateNS {
		if !claims.SuperUser && !claims.Admin {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "Only admin or super user can create namespace"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	data := &NSData{}
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
	var nsdb NSData
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

	data := &NSData{}
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

	var nsdb NSData
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
		log.Error().Str("uid", claims.UID).Str("ns", nsID).Msgf("failed to update namespace %v", err)
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

	var nsdb NSData
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namespaces := make([]NSData, 0)
	nscursor, _ := nsCollection.Find(ctx, ns)
	for nscursor.Next(ctx) {
		var nsdb NSData
		nscursor.Decode(&nsdb)
		namespaces = append(namespaces, nsdb)
	}

	resp := map[string]interface{}{"ns": namespaces}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CreateNSTemplateHandler creates a new template for namespace
var CreateNSTemplateHandler = func(w http.ResponseWriter, r *http.Request) {
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraModel.Template{}
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
	var templatedb terraModel.Template
	err = recipeCollection.FindOne(ctx, ns).Decode(&templatedb)
	if err != mongo.ErrNoDocuments {
		// already exists
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "template already exists"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	newtemplate, err := templateCollection.InsertOne(ctx, data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to create template"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	config := terraConfig.LoadConfig()
	remote := []string{config.URL, "deploy", "ns", nsID, "template", newtemplate.InsertedID.(primitive.ObjectID).Hex()}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Location", strings.Join(remote, "/"))
	w.WriteHeader(http.StatusCreated)

	resp := map[string]interface{}{"template": newtemplate.InsertedID}

	json.NewEncoder(w).Encode(resp)
}

// GetNSTemplatesHandler get namespace templates
var GetNSTemplatesHandler = func(w http.ResponseWriter, r *http.Request) {
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
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

	templates := make([]terraModel.Template, 0)
	cursor, err := templateCollection.Find(ctx, ns)
	if err != nil {
		resp := map[string]interface{}{"templates": templates}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	for cursor.Next(ctx) {
		var templatedb terraModel.Template
		cursor.Decode(&templatedb)
		templates = append(templates, templatedb)
	}

	resp := map[string]interface{}{"templates": templates}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSTemplateHandler get namespace template
var GetNSTemplateHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// nsID := vars["id"]
	templateID, _ := primitive.ObjectIDFromHex(vars["template"])
	claims, claimserr := CheckToken(r.Header.Get("Authorization"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		// "namespace": nsID,
		"_id": templateID,
	}

	var templatedb terraModel.Template
	err := templateCollection.FindOne(ctx, ns).Decode(&templatedb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "template not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	if !templatedb.Public {
		if claimserr != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", claimserr)}
			json.NewEncoder(w).Encode(respError)
			return
		}
		if !claims.Admin && !IsMemberOfNS(nsCollection, templatedb.Namespace, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	resp := map[string]interface{}{"template": templatedb}
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraModel.Recipe{}
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
	var recipedb terraModel.Recipe
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
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

	recipes := make([]terraModel.Recipe, 0)
	cursor, err := recipeCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var recipedb terraModel.Recipe
		cursor.Decode(&recipedb)
		recipes = append(recipes, recipedb)
	}

	resp := map[string]interface{}{"recipes": recipes}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetPublicRecipesHandler get namespace recipes
var GetPublicRecipesHandler = func(w http.ResponseWriter, r *http.Request) {
	_, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"public": true,
	}

	lightMode := false
	light, ok := r.URL.Query()["light"]
	if ok && light[0] == "1" {
		lightMode = true
	}

	recipes := make([]terraModel.Recipe, 0)
	cursor, err := recipeCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var recipedb terraModel.Recipe
		cursor.Decode(&recipedb)
		if lightMode {
			recipedb.Script = ""
		}
		recipes = append(recipes, recipedb)
	}

	resp := map[string]interface{}{"recipes": recipes}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetPublicEndpointsHandler returns public endpoints
var GetPublicEndpointsHandler = func(w http.ResponseWriter, r *http.Request) {
	_, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"public": true,
	}

	endpoints := make([]terraModel.EndPoint, 0)
	cursor, err := endpointCollection.Find(ctx, ns)
	if err != nil {
		resp := map[string]interface{}{"endpoints": endpoints}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	for cursor.Next(ctx) {
		var endpointdb terraModel.EndPoint
		cursor.Decode(&endpointdb)
		endpoints = append(endpoints, endpointdb)
	}

	resp := map[string]interface{}{"endpoints": endpoints}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

//GetPublicTemplatesHandler returns public templates
var GetPublicTemplatesHandler = func(w http.ResponseWriter, r *http.Request) {
	_, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"public": true,
	}

	lightMode := false
	light, ok := r.URL.Query()["light"]
	if ok && light[0] == "1" {
		lightMode = true
	}

	templates := make([]terraModel.Template, 0)
	cursor, err := templateCollection.Find(ctx, ns)
	if err != nil {
		resp := map[string]interface{}{"templates": templates}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	for cursor.Next(ctx) {
		var templatedb terraModel.Template
		cursor.Decode(&templatedb)
		if lightMode {
			templatedb.Data = make(map[string]string)
			templatedb.Model = make([]terraModel.Model, 0)
		}
		templates = append(templates, templatedb)
	}

	resp := map[string]interface{}{"templates": templates}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetNSRecipeHandler get namespace recipe
var GetNSRecipeHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// nsID := vars["id"]
	recipeID, _ := primitive.ObjectIDFromHex(vars["recipe"])
	claims, claimserr := CheckToken(r.Header.Get("Authorization"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		// "namespace": nsID,
		"_id": recipeID,
	}

	var recipedb terraModel.Recipe
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
		if !claims.Admin && !IsMemberOfNS(nsCollection, recipedb.Namespace, claims.UID) {
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraModel.Application{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	if data.Template == "" {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "missing template"}
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
	var appdb terraModel.Application
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
			possibleBaseImagesNew = false
			possibleBaseImages = append(possibleBaseImages, parentBaseImages...)
			for _, availableImage := range parentBaseImages {
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
	if len(possibleBaseImages) > 0 {
		baseImage = possibleBaseImages[0]
	}

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
	var recdb terraModel.Recipe
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
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

	apps := make([]terraModel.Application, 0)
	cursor, err := appCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var appdb terraModel.Application
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

	var appdb terraModel.Application
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
		if !claims.Admin && !IsMemberOfNS(nsCollection, appdb.Namespace, claims.UID) {
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
	Template  map[string]string            `json:"template"`
	Recipes   map[string]string            `json:"recipes"`
	EndPoints map[string]map[string]string `json:"endpoints"`
}

// getTemplateInputs get template inputs
func getTemplateInputs(template string, ns string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	templateID, _ := primitive.ObjectIDFromHex(template)
	recfilter := bson.M{
		"_id": templateID,
	}
	var recdb terraModel.Template
	recerr := templateCollection.FindOne(ctx, recfilter).Decode(&recdb)
	if recerr == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("no template found %s", template)
	}
	if !recdb.Public && recdb.Namespace != ns {
		return nil, fmt.Errorf("template is not public or in namespace %s", template)
	}
	return recdb.Inputs, nil

}

// getRecipeInputs get (sub)recipe inputs
func getRecipeInputs(recipe string, ns string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recipeID, _ := primitive.ObjectIDFromHex(recipe)
	recfilter := bson.M{
		"_id": recipeID,
	}
	var recdb terraModel.Recipe
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
		// "namespace": nsID,
		"_id": appID,
	}

	var appdb terraModel.Application
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
		if !claims.Admin && !IsMemberOfNS(nsCollection, appdb.Namespace, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	appInputs := &AppExpectedInputs{}
	var tplInputs error
	appInputs.Template, tplInputs = getTemplateInputs(appdb.Template, nsID)
	if tplInputs != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "failed to get template inputs"}
		json.NewEncoder(w).Encode(respError)
		return
	}
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
		var endpointdb terraModel.EndPoint
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

// EndPointSecret is a structure to save in db a user/password (encrypted)
type EndPointSecret struct {
	UID       string `json:"uid"`
	UserName  string `json:"name"`
	Password  string `json:"password"`
	EndPoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
}

func cryptData(data string) (string, error) {
	config := terraConfig.LoadConfig()

	//hash := hmac.New(sha256.New, []byte(config.Fernet[0]))
	//secret := hex.EncodeToString(hash.Sum(nil))
	hasher := md5.New()
	hasher.Write([]byte(config.Fernet[0]))
	secret := hex.EncodeToString(hasher.Sum(nil))

	block, cipherErr := aes.NewCipher([]byte(secret))
	if cipherErr != nil {
		log.Error().Msgf("Failed secret cypher: %s", cipherErr)
		return "", cipherErr
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	cryptedData := base64.StdEncoding.EncodeToString(ciphertext)
	return cryptedData, nil

}

func decryptData(cryptedData string) (string, error) {
	config := terraConfig.LoadConfig()

	data, _ := base64.StdEncoding.DecodeString(cryptedData)

	//hash := hmac.New(sha256.New, []byte(config.Fernet[0]))
	// secret := hex.EncodeToString(hash.Sum(nil))
	//secret := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	hasher := md5.New()
	hasher.Write([]byte(config.Fernet[0]))
	secret := hex.EncodeToString(hasher.Sum(nil))

	key := []byte(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	// byteData := []byte(data)
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// GetNSEndpointSecretHandler checks if user has a secret for this endpoint
var GetNSEndpointSecretHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	endpointID := vars["endpoint"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"uid":       claims.UID,
		"endpoint":  endpointID,
		"namespace": nsID,
	}

	eps := EndPointSecret{}
	errEps := endpointSecretCollection.FindOne(ctx, ns).Decode(&eps)
	if errEps != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": fmt.Sprintf("Could not find a secret: %s", errEps)}
		json.NewEncoder(w).Encode(respError)
		return

	}
	w.Header().Add("Content-Type", "application/json")
	respError := map[string]interface{}{"message": "secret found"}
	json.NewEncoder(w).Encode(respError)
}

// DeleteNSEndpointSecretHandler remove user secret for endpoint
var DeleteNSEndpointSecretHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	endpointID := vars["endpoint"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"uid":       claims.UID,
		"endpoint":  endpointID,
		"namespace": nsID,
	}

	_, errDel := endpointSecretCollection.DeleteOne(ctx, ns)
	if errDel != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": fmt.Sprintf("Could not delete secret: %s", errDel)}
		json.NewEncoder(w).Encode(respError)
		return

	}
	w.Header().Add("Content-Type", "application/json")
	respError := map[string]interface{}{"message": "secret removed"}
	json.NewEncoder(w).Encode(respError)
}

// CreateNSEndpointSecretHandler create/update user password for defined endpoint, password is encrypted
var CreateNSEndpointSecretHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	endpointID := vars["endpoint"]
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &EndPointSecret{}
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
		"uid":       claims.UID,
		"endpoint":  endpointID,
		"namespace": nsID,
	}

	cryptedPwd, cryptErr := cryptData(data.Password)
	if cryptErr != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": fmt.Sprintf("failed to crypt: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	var endpointdb EndPointSecret
	err = endpointSecretCollection.FindOne(ctx, ns).Decode(&endpointdb)
	if err == mongo.ErrNoDocuments {
		// create
		secret := &EndPointSecret{
			UID:       claims.UID,
			UserName:  data.UserName,
			EndPoint:  endpointID,
			Password:  cryptedPwd,
			Namespace: nsID,
		}
		endpointSecretCollection.InsertOne(ctx, secret)

	} else {
		// update
		newsecret := bson.M{
			"$set": bson.M{
				"name":     data.UserName,
				"password": cryptedPwd,
			},
		}
		endpointSecretCollection.FindOneAndUpdate(ctx, ns, newsecret)
	}
	w.Header().Add("Content-Type", "application/json")
	respError := map[string]interface{}{"message": "password set for endpoint"}
	json.NewEncoder(w).Encode(respError)
}

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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not a namespace member"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraModel.EndPoint{}
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
	var endpointdb terraModel.EndPoint
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
	if !claims.Admin && !IsMemberOfNS(nsCollection, nsID, claims.UID) {
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

	endpoints := make([]terraModel.EndPoint, 0)
	cursor, err := endpointCollection.Find(ctx, ns)
	for cursor.Next(ctx) {
		var endpointdb terraModel.EndPoint
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
	// nsID := vars["id"]
	endpointID, _ := primitive.ObjectIDFromHex(vars["endpoint"])
	claims, err := CheckToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		// "namespace": nsID,
		"_id": endpointID,
	}

	var endpointdb terraModel.EndPoint
	err = endpointCollection.FindOne(ctx, ns).Decode(&endpointdb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "endpoint not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	if !endpointdb.Public {
		if !claims.Admin && !IsMemberOfNS(nsCollection, endpointdb.Namespace, claims.UID) {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			respError := map[string]interface{}{"message": "not a namespace member"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	resp := map[string]interface{}{"endpoint": endpointdb}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// End of Endpoints ******************************

// Run *******************************************

func getTerraTemplates(userID string, nsID string, app string, run *terraModel.Run) (variablesTf string, appTf string, err error) {
	appID, _ := primitive.ObjectIDFromHex(app)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"_id": appID,
	}

	var appDb terraModel.Application
	err = appCollection.FindOne(ctx, ns).Decode(&appDb)
	if err == mongo.ErrNoDocuments {
		return "", "", fmt.Errorf("application not found")
	}
	if !appDb.Public && !IsMemberOfNS(nsCollection, appDb.Namespace, userID) {
		return "", "", fmt.Errorf("not allowed to access namespace %s by %s", appDb.Namespace, userID)
	}

	endpointID, _ := primitive.ObjectIDFromHex(run.Endpoint)
	ns = bson.M{
		// "namespace": nsID,
		"_id":       endpointID,
	}
	var endpointDb terraModel.EndPoint
	err = endpointCollection.FindOne(ctx, ns).Decode(&endpointDb)
	if err == mongo.ErrNoDocuments {
		return "", "", fmt.Errorf("endpoint not found")
	}
	if !endpointDb.Public && !IsMemberOfNS(nsCollection, endpointDb.Namespace, userID) {
		return "", "", fmt.Errorf("not allowed to access namespace %s by %s", endpointDb.Namespace, userID)
	}

	ctxTpl, cancelTpl := context.WithTimeout(context.Background(), 30*time.Second)
	tplID, _ := primitive.ObjectIDFromHex(appDb.Template)
	defer cancelTpl()
	nsTpl := bson.M{
		"_id": tplID,
	}

	var tplDb terraModel.Template
	err = templateCollection.FindOne(ctxTpl, nsTpl).Decode(&tplDb)
	if err == mongo.ErrNoDocuments {
		return "", "", fmt.Errorf("template not found")
	}

	appTf = tplDb.Data[endpointDb.Kind]
	if appTf == "" {
		return "", "", fmt.Errorf("no " + endpointDb.Kind + " template found")
	}

	if !appDb.Public && !IsMemberOfNS(nsCollection, appDb.Namespace, userID) {
		return "", "", fmt.Errorf("not allowed to access namespace %s by %s", appDb.Namespace, userID)
	}

	variablesTf = ""
	loadedVariables := make(map[string]bool)

	// Run
	for key := range run.Inputs {
		variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", key, run.Inputs[key])
		loadedVariables[key] = true
	}

	// SensitiveInputs are declared but values are added via env variables
	for key := range run.SensitiveInputs {
		variablesTf += fmt.Sprintf("variable %s {\n    default=\"\"\n}\n", key)
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
	if endpointDb.Public || IsMemberOfNS(nsCollection, endpointDb.Namespace, userID) {
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

	// Add password if not already defined
	if _, ok := loadedVariables["password"]; !ok {
		variablesTf += fmt.Sprintf("variable %s {\n    default=\"%s\"\n}\n", "password", "")
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

	run := &terraModel.Run{}
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

	run := &terraModel.Run{}
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

	sensitiveInputs := make(map[string]string)
	if run.SensitiveInputs != nil {
		for key, val := range run.SensitiveInputs {
			sensitiveInputs[key] = val
		}
	}

	// Is user_name defined in run inputs?
	userVal, userOk := run.Inputs["user_name"]
	// Is password defined in sensitive inputs?
	passwordVal, passwordOk := sensitiveInputs["password"]
	// If either is not provided, check for predefined values in endpointsecret in related endpoint
	if !passwordOk || !userOk || userVal == "" || passwordVal == "" {
		secretEndpoint := &EndPointSecret{}
		ctxSecret, cancelSecret := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelSecret()
		secretFilter := bson.M{
			"endpoint": run.Endpoint,
			"uid":      claims.UID,
		}
		errSecret := endpointSecretCollection.FindOne(ctxSecret, secretFilter).Decode(secretEndpoint)
		if errSecret == nil {
			log.Debug().Str("uid", claims.UID).Str("ns", nsID).Msg("Using user secret for endpoint")
			if !passwordOk || passwordVal == "" {
				decodedPassword, decodedErr := decryptData(secretEndpoint.Password)
				if decodedErr == nil {
					log.Error().Str("uid", claims.UID).Str("ns", nsID).Msgf("failed to decode user password for endpoint %s", run.Endpoint)
					sensitiveInputs["password"] = decodedPassword
				}
			}
			// If no user_name provided, use one defined in endpoint secret
			if !userOk || userVal == "" {
				variablesTf += fmt.Sprintf("\nvariable %s {\n    default=\"%s\"\n}\n", "user_name", secretEndpoint.UserName)

			}
		} else {
			log.Debug().Str("uid", claims.UID).Str("ns", nsID).Msg("no endpoint secret defined")
		}
	}

	config := terraConfig.LoadConfig()
	run.AppID = vars["application"]
	run.UID = claims.UID
	run.Namespace = nsID
	run.Start = time.Now().Unix()
	run.End = 0
	run.Status = "pending"
	// Clear sensitive inputs
	run.SensitiveInputs = make(map[string]string)
	run.Events = make([]terraModel.Event, 0)
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

	if run.Inputs != nil {
		runInputs, runInputsErr := json.Marshal(run.Inputs)
		if runInputsErr == nil {
			errEnvFile := ioutil.WriteFile(runPath+"/goterra.env", runInputs, 0644)
			if errEnvFile != nil {
				w.Header().Add("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				respError := map[string]interface{}{"message": "failed to write goterra.env"}
				json.NewEncoder(w).Encode(respError)
				return
			}
		}
	}

	amqpErr := SendRunAction("deploy", newrun.InsertedID.(primitive.ObjectID).Hex(), sensitiveInputs)
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

// GetNSRunsHandler get all runs (limit 50, allow paging)
var GetNSRunsHandler = func(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"uid":       claims.UID,
		"namespace": nsID,
	}

	if claims.Admin && IsOwnerOfNS(nsCollection, nsID, claims.UID) {
		getAll, ok := r.URL.Query()["all"]
		if ok {
			if getAll[0] == "1" {
				ns = bson.M{
					"namespace": nsID,
				}
			}
		}
	}

	runs := make([]terraModel.Run, 0)
	var opts mongoOptions.FindOptions
	// Get most recents first
	sortMap := make(map[string]interface{})
	sortMap["_id"] = -1
	opts.SetSort(sortMap)
	// opts.SetSort(bson.D{{"_id", -1}})
	opts.SetSkip(0)
	opts.SetLimit(50)
	skip, ok := r.URL.Query()["skip"]
	if ok {
		sval, sconvErr := strconv.ParseInt(skip[0], 0, 64)
		if sconvErr == nil {
			opts.SetSkip(sval)
		}
	}
	limit, ok := r.URL.Query()["limit"]
	if ok {
		sval, sconvErr := strconv.ParseInt(limit[0], 0, 64)
		if sconvErr == nil {
			opts.SetLimit(sval)
		}
	}
	runsCursor, err := runCollection.Find(ctx, ns, &opts)
	for runsCursor.Next(ctx) {
		var run terraModel.Run
		runsCursor.Decode(&run)
		runs = append(runs, run)
	}
	resp := map[string]interface{}{"runs": runs}
	json.NewEncoder(w).Encode(resp)
	return
}

// GetRunsHandler get all runs (limit 50, allow paging)
var GetRunsHandler = func(w http.ResponseWriter, r *http.Request) {
	// vars := mux.Vars(r)
	// nsID := vars["id"]
	claims, err := CheckToken(r.Header.Get("Authorization"))

	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"uid": claims.UID,
	}

	runs := make([]terraModel.Run, 0)
	var opts mongoOptions.FindOptions
	// Get most recents first
	sortMap := make(map[string]interface{})
	sortMap["_id"] = -1
	opts.SetSort(sortMap)
	// opts.SetSort(bson.D{{"_id", -1}})
	opts.SetSkip(0)
	opts.SetLimit(50)
	skip, ok := r.URL.Query()["skip"]
	if ok {
		sval, sconvErr := strconv.ParseInt(skip[0], 0, 64)
		if sconvErr == nil {
			opts.SetSkip(sval)
		}
	}
	limit, ok := r.URL.Query()["limit"]
	if ok {
		sval, sconvErr := strconv.ParseInt(limit[0], 0, 64)
		if sconvErr == nil {
			opts.SetLimit(sval)
		}
	}
	runsCursor, err := runCollection.Find(ctx, ns, &opts)
	for runsCursor.Next(ctx) {
		var run terraModel.Run
		runsCursor.Decode(&run)
		runs = append(runs, run)
	}
	resp := map[string]interface{}{"runs": runs}
	json.NewEncoder(w).Encode(resp)
	return
}

// GetRunHandler get some info about run
var GetRunHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	runID, _ := primitive.ObjectIDFromHex(vars["run"])
	claims, err := CheckToken(r.Header.Get("Authorization"))

	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"_id":       runID,
		"namespace": nsID,
	}
	var rundb terraModel.Run
	err = runCollection.FindOne(ctx, ns).Decode(&rundb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "run not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	rundb.SensitiveInputs = nil

	if rundb.UID != claims.UID && !claims.Admin {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not allowed to access this resource"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	json.NewEncoder(w).Encode(rundb)
}

// DeleteRunHandler asks to destroy resources
var DeleteRunHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nsID := vars["id"]
	runID, _ := primitive.ObjectIDFromHex(vars["run"])
	claims, err := CheckToken(r.Header.Get("Authorization"))

	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": fmt.Sprintf("Auth error: %s", err)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	run := terraModel.Run{}
	err = json.NewDecoder(r.Body).Decode(&run)
	if err != nil {
		log.Debug().Str("uid", claims.UID).Str("ns", nsID).Msg("Delete with no content, this is allowed....")
		//w.Header().Add("Content-Type", "application/json")
		//w.WriteHeader(http.StatusInternalServerError)
		//respError := map[string]interface{}{"message": "failed to decode message"}
		//json.NewEncoder(w).Encode(respError)
		//return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := bson.M{
		"_id":       runID,
		"namespace": nsID,
	}
	var rundb terraModel.Run
	err = runCollection.FindOne(ctx, ns).Decode(&rundb)
	if err == mongo.ErrNoDocuments {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		respError := map[string]interface{}{"message": "run not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	rundb.SensitiveInputs = nil

	if rundb.UID != claims.UID && !claims.Admin {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		respError := map[string]interface{}{"message": "not allowed to access this resource"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	sensitiveInputs := make(map[string]string)
	if run.SensitiveInputs != nil {
		for key, val := range run.SensitiveInputs {
			sensitiveInputs[key] = val
		}
	}

	if val, ok := sensitiveInputs["password"]; !ok || val == "" {
		secretEndpoint := &EndPointSecret{}
		ctxSecret, cancelSecret := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelSecret()
		secretFilter := bson.M{
			"endpoint": rundb.Endpoint,
			"uid":      claims.UID,
		}
		errSecret := endpointSecretCollection.FindOne(ctxSecret, secretFilter).Decode(secretEndpoint)
		if errSecret == nil {
			log.Debug().Str("uid", claims.UID).Str("ns", nsID).Msg("Using user secret for endpoint")
			decodedPassword, decodedErr := decryptData(secretEndpoint.Password)
			if decodedErr == nil {
				log.Printf("[ERROR] Failed to decode user %s password for endpoint %s", claims.UID, rundb.Endpoint)
				sensitiveInputs["password"] = decodedPassword
			}
		} else {
			log.Debug().Str("uid", claims.UID).Str("ns", nsID).Msg("password provided in run, skipping secret checks")
		}
	}

	ctxUpdate, updateCancel := context.WithTimeout(context.Background(), 30*time.Second)
	runFilter := bson.M{
		"_id": rundb.ID,
	}
	runUpdate := bson.M{
		"$set": bson.M{
			"status": "destroy_pending",
		},
	}

	updatedRun := terraModel.Run{}
	upErr := runCollection.FindOneAndUpdate(ctxUpdate, runFilter, runUpdate).Decode(&updatedRun)
	if upErr != nil {
		log.Error().Str("uid", claims.UID).Str("ns", nsID).Msgf("Failed to update run status: %s", upErr)
	}
	updateCancel()

	amqpErr := SendRunAction("destroy", vars["run"], sensitiveInputs)
	if amqpErr != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": fmt.Sprintf("failed to deploy:%s", amqpErr)}
		json.NewEncoder(w).Encode(respError)
		return
	}

	json.NewEncoder(w).Encode(updatedRun)
}

// End of Run ************************************

func main() {

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if os.Getenv("GOT_DEBUG") != "" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	config := terraConfig.LoadConfig()

	consulErr := terraConfig.ConsulDeclare("got-deploy", "/deploy")
	if consulErr != nil {
		log.Error().Msgf("Failed to register: %s", consulErr.Error())
		panic(consulErr)
	}

	mongoClient, err := mongo.NewClient(mongoOptions.Client().ApplyURI(config.Mongo.URL))
	if err != nil {
		log.Error().Msgf("Failed to connect to mongo server %s\n", config.Mongo.URL)
		os.Exit(1)
	}
	ctx, cancelMongo := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelMongo()

	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Error().Msgf("Failed to connect to mongo server %s\n", config.Mongo.URL)
		os.Exit(1)
	}
	nsCollection = mongoClient.Database(config.Mongo.DB).Collection("ns")
	recipeCollection = mongoClient.Database(config.Mongo.DB).Collection("recipe")
	appCollection = mongoClient.Database(config.Mongo.DB).Collection("application")
	endpointCollection = mongoClient.Database(config.Mongo.DB).Collection("endpoint")
	endpointSecretCollection = mongoClient.Database(config.Mongo.DB).Collection("endpointsecrets")
	runCollection = mongoClient.Database(config.Mongo.DB).Collection("run")
	templateCollection = mongoClient.Database(config.Mongo.DB).Collection("template")

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

	r.HandleFunc("/deploy/ns/{id}/run", GetNSRunsHandler).Methods("GET")                // Get all user runs for this NS
	r.HandleFunc("/deploy/ns/{id}/run/{application}", CreateRunHandler).Methods("POST") // deploy app
	r.HandleFunc("/deploy/ns/{id}/run/{run}", GetRunHandler).Methods("GET")
	r.HandleFunc("/deploy/ns/{id}/run/{application}/terraform", CreateRunTerraformHandlerHandler).Methods("POST") //get terraform templates for a run but do not deploy app
	r.HandleFunc("/deploy/ns/{id}/run/{run}", DeleteRunHandler).Methods("DELETE")                                 // stop run

	r.HandleFunc("/deploy/ns/{id}/endpoint", GetNSEndpointsHandler).Methods("GET")                              // get ns endpoints
	r.HandleFunc("/deploy/ns/{id}/endpoint", CreateNSEndpointHandler).Methods("POST")                           // add endpoint
	r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}", GetNSEndpointHandler).Methods("GET")                    // get endpoint
	r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}/secret", CreateNSEndpointSecretHandler).Methods("PUT")    // create/update user secret for this endpoint
	r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}/secret", DeleteNSEndpointSecretHandler).Methods("DELETE") // delete user secret for this endpoint
	r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}/secret", GetNSEndpointSecretHandler).Methods("GET")       // checks if user has a secret for this endpoint

	r.HandleFunc("/deploy/run", GetRunsHandler).Methods("GET")                  // Get all user runs
	r.HandleFunc("/deploy/recipes", GetPublicRecipesHandler).Methods("GET")     // Get public recipes
	r.HandleFunc("/deploy/templates", GetPublicTemplatesHandler).Methods("GET") // Get public templates
	r.HandleFunc("/deploy/endpoints", GetPublicEndpointsHandler).Methods("GET") // Get public endpoints

	// TODO update openapi.yaml
	// For the moment template api is not used,embeded in app definition
	r.HandleFunc("/deploy/ns/{id}/template", CreateNSTemplateHandler).Methods("POST")        // create template
	r.HandleFunc("/deploy/ns/{id}/template", GetNSTemplatesHandler).Methods("GET")           // get templates
	r.HandleFunc("/deploy/ns/{id}/template/{template}", GetNSTemplateHandler).Methods("GET") // get template
	// r.HandleFunc("/deploy/ns/{id}/template/{template}", UpdateNSTemplateHandler).Methods("PUT") // update template
	// r.HandleFunc("/deploy/ns/{id}/template/{template}", DeleteNSTemplateHandler).Methods("DELETE")  // delete template

	// r.HandleFunc("/deploy/ns/{id}/endpoint/{endpoint}", DeleteNSEndpointHandler).Methods("DELETE")  // delete endpoint

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
	})
	handler := c.Handler(r)

	loggedRouter := handlers.LoggingHandler(os.Stdout, handler)

	srv := &http.Server{
		Handler: loggedRouter,
		Addr:    fmt.Sprintf("%s:%d", config.Web.Listen, config.Web.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	srv.ListenAndServe()

}

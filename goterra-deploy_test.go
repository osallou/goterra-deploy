package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"

	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraModel "github.com/osallou/goterra-lib/lib/model"
	terraToken "github.com/osallou/goterra-lib/lib/token"
	terraUser "github.com/osallou/goterra-lib/lib/user"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"
)

var token string

var namespaces map[string]string

func TestMain(m *testing.M) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if os.Getenv("GOT_DEBUG") != "" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	os.Setenv("GOT_ACL_USER_CREATENS", "1")

	namespaces = make(map[string]string)
	setup()

	code := m.Run()
	// shutdown()
	os.Exit(code)
}

func setup() {
	user := terraUser.User{
		UID:       "test",
		Email:     "test@anonymous.org",
		Admin:     false,
		SuperUser: false,
		APIKey:    "123456",
	}
	userJSON, _ := json.Marshal(user)
	tkn, _ := terraToken.FernetEncode(userJSON)
	token = string(tkn)
	log.Debug().Msgf("Token %s", token)

	config := terraConfig.LoadConfig()
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

	mongoClient.Database(config.Mongo.DB).Drop(ctx)
	nsCollection = mongoClient.Database(config.Mongo.DB).Collection("ns")
	recipeCollection = mongoClient.Database(config.Mongo.DB).Collection("recipe")
	appCollection = mongoClient.Database(config.Mongo.DB).Collection("application")
	endpointCollection = mongoClient.Database(config.Mongo.DB).Collection("endpoint")
	endpointSecretCollection = mongoClient.Database(config.Mongo.DB).Collection("endpointsecrets")
	runCollection = mongoClient.Database(config.Mongo.DB).Collection("run")
	templateCollection = mongoClient.Database(config.Mongo.DB).Collection("template")
	endpointDefaultsCollection = mongoClient.Database(config.Mongo.DB).Collection("user_ep_defaults")
}

func _router() *mux.Router {
	r := mux.NewRouter()
	setRoutes(r)
	return r
}

func TestHomeHandler(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/deploy", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HomeHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]interface{}
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}

	if resData["message"] != "ok" {
		jsonData, _ := json.Marshal(resData)
		t.Errorf("handler returned unexpected body: got %s want %s",
			jsonData, "ok")
	}
}

func _createNS(t *testing.T, name string) (string, error) {
	data := terraModel.NSData{
		Name: name,
	}
	jsonData, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", "/deploy/ns", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusCreated {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusCreated)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["ns"], nil
}

func _updateNS(t *testing.T, ns terraModel.NSData) (string, error) {

	jsonData, _ := json.Marshal(ns)
	req, err := http.NewRequest("PUT", fmt.Sprintf("/deploy/ns/%s", ns.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["ns"], nil
}

func _deleteNS(t *testing.T, id string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s", id), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return nil
}

func _fetchNS(t *testing.T, id string) (terraModel.NSData, error) {
	var data terraModel.NSData
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s", id), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string]terraModel.NSData
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["ns"], nil
}

func _createRecipe(t *testing.T, ns terraModel.NSData, recipe terraModel.Recipe) (string, error) {
	jsonData, _ := json.Marshal(recipe)
	req, err := http.NewRequest("POST", fmt.Sprintf("/deploy/ns/%s/recipe", ns.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusCreated {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusCreated)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["recipe"], nil
}

func _updateRecipe(t *testing.T, ns terraModel.NSData, recipe terraModel.Recipe) (terraModel.Recipe, error) {
	var data terraModel.Recipe
	jsonData, _ := json.Marshal(recipe)
	req, err := http.NewRequest("PUT", fmt.Sprintf("/deploy/ns/%s/recipe/%s", ns.ID.Hex(), recipe.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]terraModel.Recipe
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["recipe"], nil
}

func _deleteRecipe(t *testing.T, ns terraModel.NSData, recipe terraModel.Recipe) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/recipe/%s", ns.ID.Hex(), recipe.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return nil
}

func _fetchRecipe(t *testing.T, ns terraModel.NSData, recipe terraModel.Recipe) (terraModel.Recipe, error) {
	var data terraModel.Recipe
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/recipe/%s", ns.ID.Hex(), recipe.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string]terraModel.Recipe
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["recipe"], nil
}

func _fetchRecipes(t *testing.T, ns terraModel.NSData, public bool) ([]terraModel.Recipe, error) {
	var req *http.Request
	var err error
	if public {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/recipes"), nil)
	} else {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/recipe", ns.ID.Hex()), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string][]terraModel.Recipe
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["recipes"], nil
}

func _createTemplate(t *testing.T, ns terraModel.NSData, template terraModel.Template) (string, error) {
	jsonData, _ := json.Marshal(template)
	req, err := http.NewRequest("POST", fmt.Sprintf("/deploy/ns/%s/template", ns.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusCreated {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusCreated)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["template"], nil
}

func _updateTemplate(t *testing.T, ns terraModel.NSData, template terraModel.Template) (terraModel.Template, error) {
	var data terraModel.Template

	jsonData, _ := json.Marshal(template)
	req, err := http.NewRequest("PUT", fmt.Sprintf("/deploy/ns/%s/template/%s", ns.ID.Hex(), template.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]terraModel.Template
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["template"], nil
}

func _deleteTemplate(t *testing.T, ns terraModel.NSData, template terraModel.Template) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/template/%s", ns.ID.Hex(), template.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return nil
}

func _fetchTemplate(t *testing.T, ns terraModel.NSData, template terraModel.Template) (terraModel.Template, error) {
	var data terraModel.Template
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/template/%s", ns.ID.Hex(), template.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string]terraModel.Template
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["template"], nil
}

func _fetchTemplates(t *testing.T, ns terraModel.NSData, public bool) ([]terraModel.Template, error) {

	var req *http.Request
	var err error
	if public {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/templates"), nil)
	} else {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/template", ns.ID.Hex()), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string][]terraModel.Template
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["templates"], nil
}

func _createApp(t *testing.T, ns terraModel.NSData, app terraModel.Application) (string, error) {
	jsonData, _ := json.Marshal(app)
	req, err := http.NewRequest("POST", fmt.Sprintf("/deploy/ns/%s/app", ns.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusCreated {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusCreated)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["app"], nil
}

func _updateApp(t *testing.T, ns terraModel.NSData, app terraModel.Application) (terraModel.Application, error) {
	var data terraModel.Application

	jsonData, _ := json.Marshal(app)
	req, err := http.NewRequest("PUT", fmt.Sprintf("/deploy/ns/%s/app/%s", ns.ID.Hex(), app.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]terraModel.Application
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["app"], nil
}

func _deleteApp(t *testing.T, ns terraModel.NSData, app terraModel.Application) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/app/%s", ns.ID.Hex(), app.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return nil
}

func _fetchApp(t *testing.T, ns terraModel.NSData, app terraModel.Application) (terraModel.Application, error) {
	var data terraModel.Application
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/app/%s", ns.ID.Hex(), app.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string]terraModel.Application
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["app"], nil
}

func _fetchApps(t *testing.T, ns terraModel.NSData, public bool) ([]terraModel.Application, error) {
	var req *http.Request
	var err error
	if public {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/apps"), nil)
	} else {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/app", ns.ID.Hex()), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string][]terraModel.Application
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["apps"], nil
}

func _createEndpoint(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint) (string, error) {
	jsonData, _ := json.Marshal(endpoint)
	req, err := http.NewRequest("POST", fmt.Sprintf("/deploy/ns/%s/endpoint", ns.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusCreated {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusCreated)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["endpoint"], nil
}

func _updateEndpoint(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint) (terraModel.EndPoint, error) {
	var data terraModel.EndPoint
	jsonData, _ := json.Marshal(endpoint)
	req, err := http.NewRequest("PUT", fmt.Sprintf("/deploy/ns/%s/endpoint/%s", ns.ID.Hex(), endpoint.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]terraModel.EndPoint
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["endpoint"], nil
}

func _deleteEndpoint(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/endpoint/%s", ns.ID.Hex(), endpoint.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return nil
}

func _fetchEndpoint(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint) (terraModel.EndPoint, error) {
	var data terraModel.EndPoint
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/endpoint/%s", ns.ID.Hex(), endpoint.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string]terraModel.EndPoint
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["endpoint"], nil
}

func _fetchEndpointSecret(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/endpoint/%s/secret", ns.ID.Hex(), endpoint.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	return nil
}

func _createEndpointSecret(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint, secret EndPointSecret) error {
	jsonData, _ := json.Marshal(secret)
	req, err := http.NewRequest("PUT", fmt.Sprintf("/deploy/ns/%s/endpoint/%s/secret", ns.ID.Hex(), endpoint.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	return nil
}

func _deleteEndpointSecret(t *testing.T, ns terraModel.NSData, endpoint terraModel.EndPoint) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/endpoint/%s/secret", ns.ID.Hex(), endpoint.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	return nil
}

func _fetchEndpoints(t *testing.T, ns terraModel.NSData, public bool) ([]terraModel.EndPoint, error) {
	var req *http.Request
	var err error
	if public {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/endpoints"), nil)
	} else {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/endpoint", ns.ID.Hex()), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string][]terraModel.EndPoint
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["endpoints"], nil
}

func _createRun(t *testing.T, ns terraModel.NSData, app terraModel.Application, run terraModel.Run) (string, error) {
	jsonData, _ := json.Marshal(run)
	req, err := http.NewRequest("POST", fmt.Sprintf("/deploy/ns/%s/run/%s", ns.ID.Hex(), app.ID.Hex()), bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusCreated {
		return "", fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string]string
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["run"], nil
}

func _fetchRun(t *testing.T, ns terraModel.NSData, run terraModel.Run) (terraModel.Run, error) {
	var data terraModel.Run
	req, err := http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/run/%s", ns.ID.Hex(), run.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return data, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData terraModel.Run
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData, nil
}

func _fetchRuns(t *testing.T, ns terraModel.NSData, namespaceOnly bool) ([]terraModel.Run, error) {
	var req *http.Request
	var err error
	if namespaceOnly {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/ns/%s/run", ns.ID.Hex()), nil)
	} else {
		req, err = http.NewRequest("GET", fmt.Sprintf("/deploy/run"), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var resData map[string][]terraModel.Run
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["runs"], nil
}

func _deleteRun(t *testing.T, ns terraModel.NSData, run terraModel.Run) error {
	jsonData, _ := json.Marshal(run)
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/run/%s", ns.ID.Hex(), run.ID.Hex()), bytes.NewBuffer(jsonData))
	//req, err := http.NewRequest("DELETE", fmt.Sprintf("/deploy/ns/%s/run/%s", ns.ID.Hex(), run.ID.Hex()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_router().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return nil
}

func TestNamespace(t *testing.T) {
	req, err := http.NewRequest("GET", "/deploy/ns", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(GetNSALLHandler)

	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var resData map[string][]terraModel.NSData
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	assert.Equal(t, len(resData["ns"]), 0)

	// Try to create a namespace
	nsID, nsErr := _createNS(t, "test1")
	if nsErr != nil {
		t.Fail()
	}
	log.Debug().Msgf("created namespace %s", nsID)
	namespaces["test1"] = nsID

	// Get ns info
	nsData, nsDataErr := _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)
	assert.True(t, len(nsData.Owners) == 1 && len(nsData.Members) == 0)

	nsData.Members = append(nsData.Members, "user")
	_, updatedErr := _updateNS(t, nsData)
	assert.True(t, updatedErr == nil, updatedErr)
	nsData, nsDataErr = _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)
	assert.True(t, len(nsData.Owners) == 1 && len(nsData.Members) == 1)

	// Try to recreate, should fail
	_, nsErr = _createNS(t, "test1")
	assert.True(t, nsErr != nil, nsErr)

	// Delete ns
	nsErr = _deleteNS(t, nsID)
	assert.True(t, nsErr == nil, nsErr)

	// Get ns info again, should not exists anymore
	_, nsDataErr = _fetchNS(t, nsID)
	assert.True(t, nsDataErr != nil, nsDataErr)

}

func TestRecipe(t *testing.T) {
	nsID, nsErr := _createNS(t, "test1")
	if nsErr != nil {
		t.Fail()
	}
	// Get ns info
	nsData, nsDataErr := _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)

	images := make([]string, 1)
	images[0] = "debian"
	recipe := terraModel.Recipe{
		Name:       "recipe1",
		BaseImages: images,
	}
	recipeID, recipeErr := _createRecipe(t, nsData, recipe)
	assert.True(t, recipeErr == nil, recipeErr)
	recipe.ID, _ = primitive.ObjectIDFromHex(recipeID)

	recipeData, recipeErr := _fetchRecipe(t, nsData, recipe)
	assert.True(t, recipeErr == nil, recipeErr)
	assert.True(t, recipeData.Name == "recipe1" && recipeData.Public == false)

	// Update recipe
	recipe.Public = true
	_, updatedErr := _updateRecipe(t, nsData, recipe)
	assert.True(t, updatedErr == nil, updatedErr)
	recipeData, recipeErr = _fetchRecipe(t, nsData, recipe)
	assert.True(t, recipeErr == nil, recipeErr)
	assert.True(t, recipeData.Name == "recipe1" && recipeData.Public == true)

	// Get all recipes
	recipes, recipesErr := _fetchRecipes(t, nsData, false)
	assert.True(t, recipesErr == nil, recipesErr)
	assert.True(t, len(recipes) > 0)

	recipes, recipesErr = _fetchRecipes(t, nsData, true)
	assert.True(t, recipesErr == nil, recipesErr)
	assert.True(t, len(recipes) > 0)

	// Delete
	recipeErr = _deleteRecipe(t, nsData, recipe)
	assert.True(t, recipeErr == nil, recipeErr)

	// Get ns info again, should not exists anymore
	_, recipeErr = _fetchRecipe(t, nsData, recipe)
	assert.True(t, recipeErr != nil, recipeErr)

}

func TestTemplate(t *testing.T) {
	nsID, nsErr := _createNS(t, "test2")
	if nsErr != nil {
		t.Fail()
	}
	// Get ns info
	nsData, nsDataErr := _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)

	tpls := make(map[string]string)
	tpls["openstack"] = "fake template"
	template := terraModel.Template{
		Name:       "tpl1",
		Data:       tpls,
		VarRecipes: make([]string, 0),
	}
	templateID, templateErr := _createTemplate(t, nsData, template)
	assert.True(t, templateErr == nil, templateErr)
	template.ID, _ = primitive.ObjectIDFromHex(templateID)

	templateData, templateErr := _fetchTemplate(t, nsData, template)
	assert.True(t, templateErr == nil, templateErr)
	assert.True(t, templateData.Name == "tpl1" && templateData.Public == false)

	// Update
	template.Public = true
	_, updatedErr := _updateTemplate(t, nsData, template)
	assert.True(t, updatedErr == nil, updatedErr)
	templateData, templateErr = _fetchTemplate(t, nsData, template)
	assert.True(t, templateErr == nil, templateErr)
	assert.True(t, templateData.Name == "tpl1" && templateData.Public == true)

	// Get all templates
	templates, templatesErr := _fetchTemplates(t, nsData, false)
	assert.True(t, templatesErr == nil, templatesErr)
	assert.True(t, len(templates) > 0)

	templates, templatesErr = _fetchTemplates(t, nsData, true)
	assert.True(t, templatesErr == nil, templatesErr)
	assert.True(t, len(templates) > 0)

	// Delete
	templateErr = _deleteTemplate(t, nsData, template)
	assert.True(t, templateErr == nil, templateErr)

	_, templateErr = _fetchTemplate(t, nsData, template)
	assert.True(t, templateErr != nil, templateErr)
}

func TestApp(t *testing.T) {
	nsID, nsErr := _createNS(t, "test3")
	if nsErr != nil {
		t.Fail()
	}
	// Get ns info
	nsData, nsDataErr := _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)

	images := make([]string, 1)
	images[0] = "debian"
	recipe := terraModel.Recipe{
		Name:       "recipeApp",
		BaseImages: images,
	}
	recipeID, recipeErr := _createRecipe(t, nsData, recipe)
	assert.True(t, recipeErr == nil, recipeErr)
	recipe.ID, _ = primitive.ObjectIDFromHex(recipeID)

	recipeVars := make([]string, 1)
	recipeVars[0] = "recipes"

	tpls := make(map[string]string)
	tpls["openstack"] = "fake template"
	template := terraModel.Template{
		Name:       "tplapptest",
		Data:       tpls,
		VarRecipes: recipeVars,
	}
	templateID, templateErr := _createTemplate(t, nsData, template)
	assert.True(t, templateErr == nil, templateErr)
	template.ID, _ = primitive.ObjectIDFromHex(templateID)

	app := terraModel.Application{}
	app.Name = "sample app"
	app.Template = templateID
	app.TemplateRecipes = make(map[string][]string)
	app.TemplateRecipes["recipes"] = make([]string, 1)
	app.TemplateRecipes["recipes"][0] = recipeID

	appID, appErr := _createApp(t, nsData, app)
	app.ID, _ = primitive.ObjectIDFromHex(appID)
	assert.True(t, appErr == nil, appErr)

	appData, appErr := _fetchApp(t, nsData, app)
	assert.True(t, appErr == nil, appErr)
	assert.True(t, appData.Name == app.Name && appData.Public == false)

	// Update
	appData.Public = true
	_, updatedErr := _updateApp(t, nsData, appData)
	assert.True(t, updatedErr == nil, updatedErr)
	appData, appErr = _fetchApp(t, nsData, app)
	assert.True(t, appErr == nil, appErr)
	assert.True(t, appData.Name == app.Name && appData.Public == true)

	// Get all templates
	apps, appsErr := _fetchApps(t, nsData, false)
	assert.True(t, appsErr == nil, appsErr)
	assert.True(t, len(apps) > 0)

	// Get all public templates
	apps, appsErr = _fetchApps(t, nsData, true)
	assert.True(t, appsErr == nil, appsErr)
	assert.True(t, len(apps) > 0)

	// Try to delete recipe used by app
	recipeErr = _deleteRecipe(t, nsData, recipe)
	assert.True(t, recipeErr != nil, recipeErr)

	// Try to delete template used by app
	templateErr = _deleteTemplate(t, nsData, template)
	assert.True(t, templateErr != nil, templateErr)

	// Delete
	appErr = _deleteApp(t, nsData, app)
	assert.True(t, appErr == nil, appErr)

	_, appErr = _fetchApp(t, nsData, app)
	assert.True(t, appErr != nil, appErr)
}

func TestEndpoint(t *testing.T) {
	nsID, nsErr := _createNS(t, "test0")
	if nsErr != nil {
		t.Fail()
	}
	// Get ns info
	nsData, nsDataErr := _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)

	images := make(map[string]string)
	images["debian"] = "000000000"

	endpoint := terraModel.EndPoint{
		Name:   "endpoint1",
		Public: true,
		Kind:   "test",
		Images: images,
	}
	endpointID, endpointErr := _createEndpoint(t, nsData, endpoint)
	assert.True(t, endpointErr == nil, endpointErr)
	endpoint.ID, _ = primitive.ObjectIDFromHex(endpointID)

	endpointData, endpointErr := _fetchEndpoint(t, nsData, endpoint)
	assert.True(t, endpointErr == nil, endpointErr)
	assert.True(t, endpointData.Name == "endpoint1" && endpointData.Public == true)

	// Get all endpoints
	endpoints, endpointsErr := _fetchEndpoints(t, nsData, false)
	assert.True(t, endpointsErr == nil, endpointsErr)
	assert.True(t, len(endpoints) > 0)

	endpoints, endpointsErr = _fetchEndpoints(t, nsData, true)
	assert.True(t, endpointsErr == nil, endpointsErr)
	assert.True(t, len(endpoints) > 0)

	// Check there is no secret
	secretErr := _fetchEndpointSecret(t, nsData, endpoint)
	assert.True(t, secretErr != nil)
	newSecret := EndPointSecret{
		UserName: "me",
		Password: "test",
	}
	secretErr = _createEndpointSecret(t, nsData, endpoint, newSecret)
	assert.True(t, secretErr == nil, secretErr)

	secretErr = _fetchEndpointSecret(t, nsData, endpoint)
	assert.True(t, secretErr == nil, secretErr)

	secretErr = _deleteEndpointSecret(t, nsData, endpoint)
	assert.True(t, secretErr == nil, secretErr)

	secretErr = _fetchEndpointSecret(t, nsData, endpoint)
	assert.True(t, secretErr != nil)

	// Delete
	endpointErr = _deleteEndpoint(t, nsData, endpoint)
	assert.True(t, endpointErr == nil, endpointErr)

	// Get ns info again, should not exists anymore
	_, endpointErr = _fetchEndpoint(t, nsData, endpoint)
	assert.True(t, endpointErr != nil, endpointErr)

}

func TestRun(t *testing.T) {
	nsID, nsErr := _createNS(t, "test4")
	if nsErr != nil {
		t.Fail()
	}
	// Get ns info
	nsData, nsDataErr := _fetchNS(t, nsID)
	assert.True(t, nsDataErr == nil, nsDataErr)

	images := make([]string, 1)
	images[0] = "debian"
	recipe := terraModel.Recipe{
		Name:       "recipeApp",
		BaseImages: images,
	}
	recipeID, recipeErr := _createRecipe(t, nsData, recipe)
	assert.True(t, recipeErr == nil, recipeErr)
	recipe.ID, _ = primitive.ObjectIDFromHex(recipeID)

	recipeVars := make([]string, 1)
	recipeVars[0] = "recipes"

	tpls := make(map[string]string)
	tpls["openstack"] = "fake template"
	template := terraModel.Template{
		Name:       "tplapptest",
		Data:       tpls,
		VarRecipes: recipeVars,
	}
	templateID, templateErr := _createTemplate(t, nsData, template)
	assert.True(t, templateErr == nil, templateErr)
	template.ID, _ = primitive.ObjectIDFromHex(templateID)

	app := terraModel.Application{}
	app.Name = "sample app"
	app.Template = templateID
	app.TemplateRecipes = make(map[string][]string)
	app.TemplateRecipes["recipes"] = make([]string, 1)
	app.TemplateRecipes["recipes"][0] = recipeID

	appID, appErr := _createApp(t, nsData, app)
	app.ID, _ = primitive.ObjectIDFromHex(appID)
	assert.True(t, appErr == nil, appErr)

	endpointImages := make(map[string]string)
	endpointImages["debian"] = "000000000"

	endpoint := terraModel.EndPoint{
		Name:   "endpoint1",
		Public: true,
		Kind:   "openstack",
		Images: endpointImages,
	}
	endpointID, endpointErr := _createEndpoint(t, nsData, endpoint)
	assert.True(t, endpointErr == nil, endpointErr)
	endpoint.ID, _ = primitive.ObjectIDFromHex(endpointID)

	newSecret := EndPointSecret{
		UserName: "me",
		Password: "test",
	}
	secretErr := _createEndpointSecret(t, nsData, endpoint, newSecret)
	assert.True(t, secretErr == nil, secretErr)

	inputs := make(map[string]string)
	inputs["ssh_pub_key"] = "fakepubkey"

	run := terraModel.Run{
		Name:     "runtest",
		AppID:    appID,
		Inputs:   inputs,
		Endpoint: endpointID,
	}

	os.Setenv("GOT_MOCK_AMQP", "1")

	runID, runErr := _createRun(t, nsData, app, run)
	assert.True(t, runErr == nil, runErr)
	run.ID, _ = primitive.ObjectIDFromHex(runID)

	pendingRun, pendingRunErr := _fetchRun(t, nsData, run)
	assert.True(t, pendingRunErr == nil, pendingRunErr)
	assert.True(t, pendingRun.Status == "deploy_pending")

	// Jobs in namespace
	pendingRuns, pendingRunsErr := _fetchRuns(t, nsData, false)
	assert.True(t, pendingRunsErr == nil, pendingRunsErr)
	assert.True(t, len(pendingRuns) > 0)

	// User jobs
	pendingRuns, pendingRunsErr = _fetchRuns(t, nsData, true)
	assert.True(t, pendingRunsErr == nil, pendingRunsErr)
	assert.True(t, len(pendingRuns) > 0)

	deleteErr := _deleteRun(t, nsData, run)
	assert.True(t, deleteErr == nil, deleteErr)

	pendingRuns, pendingRunsErr = _fetchRuns(t, nsData, true)
	assert.True(t, pendingRunsErr == nil, pendingRunsErr)
	assert.True(t, len(pendingRuns) > 0)
	var status = ""
	for _, pendingRun := range pendingRuns {
		if pendingRun.ID == run.ID {
			status = pendingRun.Status
			break
		}
	}
	assert.True(t, status == "destroy_pending")

}

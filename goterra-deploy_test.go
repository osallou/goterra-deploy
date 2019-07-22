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

func _updateNS(t *testing.T, ns NSData) (string, error) {

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

func _fetchNS(t *testing.T, id string) (NSData, error) {
	var data NSData
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
	var resData map[string]NSData
	// Check the response body is what we expect.
	errData := json.NewDecoder(rr.Body).Decode(&resData)
	if errData != nil {
		t.Errorf("Invalid response %+v", errData)
	}
	return resData["ns"], nil
}

func _createRecipe(t *testing.T, ns NSData, recipe terraModel.Recipe) (string, error) {
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

func _updateRecipe(t *testing.T, ns NSData, recipe terraModel.Recipe) (terraModel.Recipe, error) {
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

func _deleteRecipe(t *testing.T, ns NSData, recipe terraModel.Recipe) error {
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

func _fetchRecipe(t *testing.T, ns NSData, recipe terraModel.Recipe) (terraModel.Recipe, error) {
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

func _createTemplate(t *testing.T, ns NSData, template terraModel.Template) (string, error) {
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

func _updateTemplate(t *testing.T, ns NSData, template terraModel.Template) (terraModel.Template, error) {
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

func _deleteTemplate(t *testing.T, ns NSData, template terraModel.Template) error {
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

func _fetchTemplate(t *testing.T, ns NSData, template terraModel.Template) (terraModel.Template, error) {
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

func _createApp(t *testing.T, ns NSData, app terraModel.Application) (string, error) {
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

func _updateApp(t *testing.T, ns NSData, app terraModel.Application) (terraModel.Application, error) {
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

func _deleteApp(t *testing.T, ns NSData, app terraModel.Application) error {
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

func _fetchApp(t *testing.T, ns NSData, app terraModel.Application) (terraModel.Application, error) {
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
	var resData map[string][]NSData
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

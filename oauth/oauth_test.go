package oauth

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	fmt.Println("start oauth testing")
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsNotPublic(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "localhost:8080/oauth/access_token", strings.NewReader(""))
	isPublic := IsPublic(request)

	assert.NotNil(t, isPublic)
	assert.EqualValues(t, false, isPublic)
	assert.False(t, isPublic)
}

func TestIsPublic(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Set("X-Public", "true")

	isPublic := IsPublic(&request)
	assert.NotNil(t, isPublic)
	assert.True(t, isPublic)
}

func TestIsPublicWithNilRequest(t *testing.T) {
	isPublic := IsPublic(nil)
	assert.NotNil(t, isPublic)
	assert.EqualValues(t, true, isPublic)
	assert.True(t, isPublic)
}

func TestGetCallerIdWithNilRequest(t *testing.T) {
	assert.NotNil(t, GetCallerId(nil))
	assert.EqualValues(t, 0, GetCallerId(nil))
}

func TestGetCallerIdInvalidCallerFormat(t *testing.T) {
	header := make(map[string][]string)
	header["X-Caller-Id"] = []string{"a"}
	request := http.Request{
		Header: header,
	}
	assert.NotNil(t, GetCallerId(&request))
	assert.EqualValues(t, 0, GetCallerId(&request))
}

func TestGetCallerIdSuccess(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Set("X-Caller-Id", "1")
	assert.NotNil(t, GetCallerId(&request))
	assert.EqualValues(t, 1, GetCallerId(&request))
}

func TestGetClientIdWithNilRequest(t *testing.T) {
	assert.NotNil(t, GetClientId(nil))
	assert.EqualValues(t, 0, GetClientId(nil))
}

func TestGetClientIdInvalidCallerFormat(t *testing.T) {
	header := make(map[string][]string)
	header["X-Client-Id"] = []string{"a"}
	request := http.Request{
		Header: header,
	}
	assert.NotNil(t, GetClientId(&request))
	assert.EqualValues(t, 0, GetClientId(&request))
}

func TestGetClientIdSuccess(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Set("X-Client-Id", "1")
	assert.NotNil(t, GetClientId(&request))
	assert.EqualValues(t, 1, GetClientId(&request))
}

func TestCleanRequest(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Set("X-Client-Id", "1")
	cleanRequest(&request)
	assert.EqualValues(t, "", request.Header.Get("X-Client-Id"))
}

func TestCleanRequestWithNilRequest(t *testing.T) {
	request := http.Request{}
	cleanRequest(nil)
	assert.EqualValues(t, request, request)
}

func TestGetAccessTokenSuccess(t *testing.T) {
	//oauthRestClient.GetClient()
	defer httpmock.Reset()
	accessTokenId := "jimmy123"
	fixture := `{"access_token":"jimmy123","user_id":1,"client_id":2,"expires":123}`
	responder := httpmock.NewStringResponder(200, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())
	response, err := getAccessToken(accessTokenId)

	assert.Nil(t, err)
	assert.NotNil(t, response)
}

func TestGetAccessTokenUrlError(t *testing.T) {
	accessTokenId := ""
	response, err := getAccessToken(accessTokenId)

	assert.Nil(t, response)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
}

func TestGetAccessTokenWithTokenNotFoundError(t *testing.T) {
	defer httpmock.Reset()
	accessTokenId := "jimmy1234"
	fixture := `{"message":"token not exist","status":404,"error":"not found","causes":null}`
	responder := httpmock.NewStringResponder(404, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())
	response, err := getAccessToken(accessTokenId)

	assert.Nil(t, response)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusNotFound, err.Status())
}

func TestGetAccessTokenWithTokenNotFoundAndInvalidJsonResponse(t *testing.T) {
	defer httpmock.Reset()
	accessTokenId := "jimmy1234"
	fixture := `{"message":"token not exist","status":"404","error":"not found","causes":null}`
	responder := httpmock.NewStringResponder(404, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())
	response, err := getAccessToken(accessTokenId)

	assert.Nil(t, response)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
}

func TestGetAccessTokenInvalidJsonResponse(t *testing.T) {
	defer httpmock.Reset()
	accessTokenId := "jimmy123"
	fixture := `{"access_token":"jimmy123","user_id":"1","client_id":2,"expires":123}`
	responder := httpmock.NewStringResponder(200, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	response, err := getAccessToken(accessTokenId)

	assert.Nil(t, response)
	assert.NotNil(t, err)
	assert.EqualValues(t, "invalid response body when unmarshal response to token", err.Message())
}

func TestAuthenticateRequestWithNilRequest(t *testing.T) {
	assert.Nil(t, AuthenticateRequest(nil))
}

func TestAuthenticateRequestWithEmptyAccessTokenQueryString(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://localhost:8080", strings.NewReader(""))
	params := make(map[string]string)
	params["access_token"] = " "
	mux.SetURLVars(request, params)
	result := AuthenticateRequest(request)
	//request.URL.Query().Set("access_token", "")
	assert.Nil(t, result)
}

func TestAuthenticateRequestWithGetAccessTokenNotFoundError(t *testing.T) {
	accessTokenId := "jimmy1234"
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:8080?access_token=%s", accessTokenId), strings.NewReader(""))

	defer httpmock.Reset()
	fixture := `{"message":"token not exist","status":404,"error":"not found","causes":null}`
	responder := httpmock.NewStringResponder(404, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())

	result := AuthenticateRequest(request)

	assert.Nil(t, result)
}

func TestAuthenticateRequestWithGetAccessTokenServerError(t *testing.T) {
	accessTokenId := "jimmy1234"
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:8080?access_token=%s", accessTokenId), strings.NewReader(""))

	defer httpmock.Reset()
	fixture := `{"message":"server error","status":500,"error":"database error","causes":null}`
	responder := httpmock.NewStringResponder(500, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())

	result := AuthenticateRequest(request)

	assert.NotNil(t, result)
}

func TestAuthenticateRequestSuccess(t *testing.T) {
	accessTokenId := "jimmy123"
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:8080?access_token=%s", accessTokenId), strings.NewReader(""))

	defer httpmock.Reset()
	fixture := `{"access_token":"jimmy123","user_id":1,"client_id":2,"expires":123}`
	responder := httpmock.NewStringResponder(200, fixture)
	fakeUrl := fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId)
	httpmock.RegisterResponder("GET", fakeUrl, responder)
	httpmock.ActivateNonDefault(oauthRestClient.GetClient())

	result := AuthenticateRequest(request)

	assert.Nil(t, result)
}





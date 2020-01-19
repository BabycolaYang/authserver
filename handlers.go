// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"encoding/gob"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"encoding/hex"
	"encoding/json"
	"time"
	"strconv"
)

const (
	userSessionCookie 		 = "authservice_session"
	defaultEncryptionKey	 = "9905D3E4FFE65BA4A123CA5A8C3F3EBD25000EC2E94B94048312F880B556A3DC"
	defaultEncryptionIv		 =  "817D4264A77F682F5DE37D32F41FF604"
	defaultPenddingTime 	 = "600000000"
	//defaultOrigin			 = "http://192.168.51.45"
)


func init() {
	// Register type for claims.
	gob.Register(map[string]interface{}{})
	gob.Register(oauth2.Token{})
	gob.Register(oidc.IDToken{})
}


func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {
	
	logger := loggerForRequest(r)
	
	// Check header for auth information.
	// Adding it to a cookie to treat both cases uniformly.
	// This is also required by the gorilla/sessions package.
	// TODO(yanniszark): change to standard 'Authorization: Bearer <value>' header
	bearer := r.Header.Get("X-Auth-Token")
	if bearer != "" {
		r.AddCookie(&http.Cookie{
			Name:   userSessionCookie,
			Value:  bearer,
			Path:   "/",
			MaxAge: 1,
		})
	}

	// Check if user session is valid
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		returnStatus(w, http.StatusOK, "{success:false,msg:Couldn't get user session}")
		return
	}
	// User is logged in
	if !session.IsNew {
		// Add userid header
		userID := session.Values["userid"].(string)
		//userID := "dsglkjg"
		if userID != "" {
			w.Header().Set(s.userIDOpts.header, s.userIDOpts.prefix+userID)
		}
		logger.Info(userID)
		// if s.userIDOpts.tokenHeader != "" {
		// 	w.Header().Set(s.userIDOpts.tokenHeader, session.Values["idtoken"].(string))
		// }
		returnStatus(w, http.StatusOK, "OK")
		return
	}

	// User is NOT logged in.
	// Initiate OIDC Flow with Authorization Request.
	//state := newState(r.URL.String())
	//id, err := state.save(s.store)
	// if err != nil {
	// 	logger.Errorf("Failed to save state in store: %v", err)
	// 	returnStatus(w, http.StatusInternalServerError, "Failed to save state in store.")
	// 	return
	// }

	
	http.Redirect(w, r, s.redirectURL, http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
		
	logger := loggerForRequest(r)

	// Get authorization code from authorization response.
	var idToken = r.FormValue("idtoken")
	var origin = r.FormValue("origin")
	if len(idToken) == 0 {
		logger.Error("Missing url parameter: idtoken")
		returnStatus(w, http.StatusOK, "{success:false,msg:Missing url parameter: idtoken}")
		return
	}

	//aes
	encryptionKey := getEnvOrDefault("ENCRYPTION_KEY", defaultEncryptionKey)
	encryptionIv := getEnvOrDefault("ENCRYPTION_IV", defaultEncryptionIv)
	penddingTime := getEnvOrDefault("PENDDING_TIME", defaultPenddingTime)
	//origin := getEnvOrDefault("ORIGIN", defaultOrigin)

	decoded, err := hex.DecodeString(encryptionKey)
	if err != nil {
		logger.Error("encryptionKey is broken")
	}
	iv, err := hex.DecodeString(encryptionIv)
	if err != nil {
		logger.Error("encryptionIv is broken")
	}
	idTokenHex,err := hex.DecodeString(idToken)
	logger.Info(idToken)
	ds, err := aesDecrypt(idTokenHex,decoded,iv)
	dsString := strings.Split(string(ds),"}")[0] + "}"
	logger.Info(dsString)

	if err != nil {
		logger.Errorf("Failed to decrypt the token")
		returnStatus(w, http.StatusOK, "Failed to retrieve state.")
		return
	}
	var dat map[string]interface{}
    if err := json.Unmarshal([]byte(dsString), &dat); err == nil {
        logger.Info(dat)
	}
	email := dat["email"].(string)
	currentTime := time.Now().UnixNano() / 1e6
	logger.Info(currentTime)
	penddingTimeInt,err := strconv.ParseInt(penddingTime,10,64)
	logger.Info(penddingTimeInt)
	timestampInt,err := strconv.ParseInt(dat["timestamp"].(string),10,64)
	logger.Info(currentTime - timestampInt)
	if currentTime - timestampInt >= penddingTimeInt {
		logger.Errorf("timeout")
		returnStatus(w, http.StatusOK, "{success:false,msg:timeout}")
		return
	}
	// Get state and:
	// 1. Confirm it exists in our memory.
	// 2. Get the original URL associated with it.
	// var stateID = r.FormValue("state")
	// if len(stateID) == 0 {
	// 	logger.Error("Missing url parameter: state")
	// 	returnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
	// 	return
	// }

	// If state is loaded, then it's correct, as it is saved by its id.
	// state, err := load(s.store, stateID)
	// if err != nil {
	// 	logger.Errorf("Failed to retrieve state from store: %v", err)
	// 	returnStatus(w, http.StatusInternalServerError, "Failed to retrieve state.")
	// }

	// Exchange the authorization code with {access, refresh, id}_token
	// oauth2Token, err := s.oauth2Config.Exchange(r.Context(), authCode)
	// if err != nil {
	// 	logger.Errorf("Failed to exchange authorization code with token: %v", err)
	// 	returnStatus(w, http.StatusInternalServerError, "Failed to exchange authorization code with token.")
	// 	return
	// }

	// rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	// if !ok {
	// 	logger.Error("No id_token field available.")
	// 	returnStatus(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
	// 	return
	// }

	// Verifying received ID token
	// verifier := s.provider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})
	// _, err = verifier.Verify(r.Context(), rawIDToken)
	// if err != nil {
	// 	logger.Errorf("Not able to verify ID token: %v", err)
	// 	returnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
	// 	return
	// }

	// UserInfo endpoint to get claims
	// claims := map[string]interface{}{}
	// userInfo, err := s.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(oauth2Token))
	// if err != nil {
	// 	logger.Errorf("Not able to fetch userinfo: %v", err)
	// 	returnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
	// 	return
	// }

	// if err = userInfo.Claims(&claims); err != nil {
	// 	logger.Println("Problem getting userinfo claims:", err.Error())
	// 	returnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
	// 	return
	// }

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, userSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"

	session.Values["userid"] = email
	session.Values["origin"] = origin
	logger.Info(email)
	//session.Values["claims"] = string(ds)
	//session.Values["idtoken"] = string(ds)
	//session.Values["oauth2token"] = string(ds)
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
	}
	logger.Info("and")
	//logger.Info("Login validated with ID token, redirecting.")

	// Getting original destination from DB with state
	// var destination = state.origURL
	// if s.staticDestination != "" {
	// 	destination = s.staticDestination
	// }
	
	//returnStatus(w, http.StatusOK, "{success:true,msg:login success}")
	logger.Info(origin)
	w.Header().Set("Access-Control-Allow-Origin", origin)//允许访问所有域
	w.Header().Set("Access-Control-Allow-Method", "POST,GET,OPTIONS,DELETE")//允许访问所有域
	w.Header().Add("Access-Control-Allow-Headers","Content-Type")//header的类型
	w.Header().Set("content-type","application/json")//返回数据格式是json	
	w.Header().Set("Access-Control-Allow-Credentials","true")//返回数据格式是json
	http.Redirect(w, r, "/loginSuccess", http.StatusFound)
}

func (s *server) callbackOption(w http.ResponseWriter, r *http.Request) {
	returnStatus(w, http.StatusOK, "{success:true}")
}
// logout is the handler responsible for revoking the user's session.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	
	logger := loggerForRequest(r)
	//origin := getEnvOrDefault("ORIGIN", defaultOrigin)

	// Revoke user session.
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if session.IsNew {
		logger.Warn("Request doesn't have a valid session.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	origin := session.Values["origin"].(string)
	session.Options.MaxAge = -1
	if err := sessions.Save(r, w); err != nil {
		logger.Errorf("Couldn't delete user session: %v", err)
	}
	logger.Info("Successful logout.")
	//returnStatus(w, http.StatusOK, "{success:true,msg:login success}")
	w.Header().Set("Access-Control-Allow-Origin", origin)//允许访问所有域
	w.Header().Set("Access-Control-Allow-Method", "POST,GET,OPTIONS,DELETE")//允许访问所有域
	w.Header().Add("Access-Control-Allow-Headers","Content-Type")//header的类型
	w.Header().Set("content-type","application/json")//返回数据格式是json	
	w.Header().Set("Access-Control-Allow-Credentials","true")//返回数据格式是json
	http.Redirect(w, r, origin, http.StatusFound)
}

// readiness is the handler that checks if the authservice is ready for serving
// requests.
// Currently, it checks if the provider is nil, meaning that the setup hasn't finished yet.
func readiness(isReady *abool.AtomicBool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusOK
		if !isReady.IsSet() {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
	}
}

// func whitelistMiddleware(whitelist []string, isReady *abool.AtomicBool) func(http.Handler) http.Handler {
// 	return func(handler http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			logger := loggerForRequest(r)
// 			// Check whitelist
// 			for _, prefix := range whitelist {
// 				if strings.HasPrefix(r.URL.Path, prefix) {
// 					logger.Infof("URI is whitelisted. Accepted without authorization.")
// 					returnStatus(w, http.StatusOK, "OK")
// 					return
// 				}
// 			}
// 			// If server is not ready, return 503.
// 			if !isReady.IsSet() {
// 				returnStatus(w, http.StatusServiceUnavailable, "OIDC Setup is not complete yet.")
// 				return
// 			}
// 			// Server ready, continue.
// 			handler.ServeHTTP(w, r)
// 		})
// 	}
// }

// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
    "crypto/cipher"
    "crypto/aes"
    //"encoding/base64"
)

//const defaultOrigin			 = "http://192.168.51.45"

func loggerForRequest(r *http.Request) *log.Entry {
	return log.WithContext(r.Context()).WithFields(log.Fields{
		"ip":      getUserIP(r),
		"request": r.URL.String(),
	})
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {

	// origin := getEnvOrDefault("ORIGIN", defaultOrigin)

	// w.Header().Set("Access-Control-Allow-Origin", origin)//允许访问所有域
	// w.Header().Set("Access-Control-Allow-Method", "POST,GET,OPTIONS,DELETE")//允许访问所有域
	// w.Header().Add("Access-Control-Allow-Headers","Content-Type")//header的类型
	// w.Header().Set("content-type","application/json")//返回数据格式是json	
	// w.Header().Set("Access-Control-Allow-Credentials","true")//返回数据格式是json	
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
}

func getEnvOrDefault(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Println("No ", key, " specified, using '"+fallback+"' as default.")
		return fallback
	}
	return value
}

func getURLEnvOrDie(URLEnv string) *url.URL {
	envContent := os.Getenv(URLEnv)
	parsedURL, err := url.Parse(envContent)
	if err != nil {
		log.Fatal("Not a valid URL for env variable ", URLEnv, ": ", envContent, "\n")
	}

	return parsedURL
}

func getEnvOrDie(envVar string) string {
	envContent := os.Getenv(envVar)

	if len(envContent) == 0 {
		log.Fatal("Env variable ", envVar, " missing, exiting.")
	}

	return envContent
}

func clean(s []string) []string {
	res := []string{}
	for _, elem := range s {
		if elem != "" {
			res = append(res, elem)
		}
	}
	return res
}

func createNonce(length int) string {
	nonceChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	var nonce = make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

// func AesEncrypt(encodeStr string, key string ,iv string) (string, error) {
//     encodeBytes := []byte(encodeStr)
//     //根据key 生成密文
//     block, err := aes.NewCipher([]byte(key))
//     if err != nil {
//         return "", err
//     }

//     blockSize := block.BlockSize()
//     encodeBytes = PKCS5Padding(encodeBytes, blockSize)

//     blockMode := cipher.NewCBCEncrypter(block, []byte(iv))
//     crypted := make([]byte, len(encodeBytes))
//     blockMode.CryptBlocks(crypted, encodeBytes)

//     return base64.StdEncoding.EncodeToString(crypted), nil
// }

// func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
//     padding := blockSize - len(ciphertext)%blockSize
//     //填充
//     padtext := bytes.Repeat([]byte{byte(padding)}, padding)

//     return append(ciphertext, padtext...)
// }

func aesDecrypt(decodeStr []byte, key []byte ,iv []byte) ([]byte, error) {
    //先解密base64
    decodeBytes := decodeStr
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockMode := cipher.NewCBCDecrypter(block, iv)
    origData := make([]byte, len(decodeBytes))

    blockMode.CryptBlocks(origData, decodeBytes)
    //origData = pKCS5UnPadding(origData)
    return origData, nil
}

// func pKCS5UnPadding(origData []byte) []byte {
//     length := len(origData)
//     unpadding := int(origData[length-1])
//     return origData[:(length - unpadding)]
// }
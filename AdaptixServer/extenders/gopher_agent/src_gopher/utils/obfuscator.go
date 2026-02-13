package utils

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type Base64Obfuscator struct {
	noiseChars string
	rng        *rand.Rand
}

func NewBase64Obfuscator(seed int64) *Base64Obfuscator {
	noiseChars := "!@#$%^*()_[]{}|;:,.<>?~"

	var rng *rand.Rand
	if seed > 0 {
		rng = rand.New(rand.NewSource(seed))
	} else {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	return &Base64Obfuscator{
		noiseChars: noiseChars,
		rng:        rng,
	}
}

func (o *Base64Obfuscator) Encode(data []byte) string {
	b64Data := base64.StdEncoding.EncodeToString(data)
	obfuscated := o.insertNoise(b64Data)
	return obfuscated
}

func (o *Base64Obfuscator) EncodeString(data string) string {
	return o.Encode([]byte(data))
}

func (o *Base64Obfuscator) Decode(obfuscatedData string) ([]byte, error) {
	cleanB64 := o.removeNoise(obfuscatedData)
	originalData, err := base64.StdEncoding.DecodeString(cleanB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %v", err)
	}
	return originalData, nil
}

func (o *Base64Obfuscator) DecodeString(obfuscatedData string) (string, error) {
	data, err := o.Decode(obfuscatedData)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (o *Base64Obfuscator) insertNoise(b64String string) string {
	if len(b64String) == 0 {
		return b64String
	}

	var result strings.Builder
	result.Grow(len(b64String) * 2)

	index := 0

	for index < len(b64String) {
		currentChar := b64String[index]
		result.WriteByte(currentChar)

		offset := (int(currentChar) % 5) + 1

		index++

		if index < len(b64String) {
			skipCount := 0
			for skipCount < offset && index < len(b64String) {
				result.WriteByte(b64String[index])
				index++
				skipCount++
			}

			if index < len(b64String) {
				noiseChar := o.noiseChars[o.rng.Intn(len(o.noiseChars))]
				result.WriteByte(noiseChar)
			}
		}
	}

	return result.String()
}

func (o *Base64Obfuscator) removeNoise(obfuscatedString string) string {
	if len(obfuscatedString) == 0 {
		return obfuscatedString
	}

	var result strings.Builder
	result.Grow(len(obfuscatedString))

	index := 0

	b64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	isBase64Char := func(c byte) bool {
		return strings.ContainsRune(b64Chars, rune(c))
	}

	for index < len(obfuscatedString) {
		currentChar := obfuscatedString[index]

		if isBase64Char(currentChar) {
			result.WriteByte(currentChar)

			offset := (int(currentChar) % 5) + 1

			index++

			skipCount := 0
			for skipCount < offset && index < len(obfuscatedString) {
				if isBase64Char(obfuscatedString[index]) {
					result.WriteByte(obfuscatedString[index])
					skipCount++
				}
				index++
			}

			if index < len(obfuscatedString) && !isBase64Char(obfuscatedString[index]) {
				index++
			}
		} else {
			index++
		}
	}

	return result.String()
}

func Obfuscate(data []byte) string {
	obf := NewBase64Obfuscator(42)
	return obf.Encode(data)
}

func Deobfuscate(obfuscated string) ([]byte, error) {
	obf := NewBase64Obfuscator(42)
	return obf.Decode(obfuscated)
}

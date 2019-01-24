package TLSSigAPI

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"
)

var (
	ErrorIdentifierNotMatch = errors.New("identifier not match")
	ErrorAppidNotMatch      = errors.New("appid not match")
	ErrorExpired            = errors.New("expired")
	ErrorInvalidSignature   = errors.New("invalid signature")
	signArray               = []string{
		"TLS.appid_at_3rd",
		"TLS.account_type",
		"TLS.identifier",
		"TLS.sdk_appid",
		"TLS.time",
		"TLS.expire_after",
	}
	signUserbufArray = []string{
		"TLS.appid_at_3rd",
		"TLS.account_type",
		"TLS.identifier",
		"TLS.sdk_appid",
		"TLS.time",
		"TLS.expire_after",
		"TLS.userbuf",
	}
)

type ecdsaSignature struct {
	R, S *big.Int
}

func generateSignContent(obj map[string]string) string {
	var buffer bytes.Buffer
	for _, key := range signArray {
		buffer.WriteString(key)
		buffer.WriteString(":")
		buffer.WriteString(obj[key])
		buffer.WriteString("\n")
	}
	return buffer.String()
}

func generateSignContentWithUserbuf(obj map[string]string) string {
	var buffer bytes.Buffer
	for _, key := range signUserbufArray {
		buffer.WriteString(key)
		buffer.WriteString(":")
		buffer.WriteString(obj[key])
		buffer.WriteString("\n")
	}
	return buffer.String()
}

func sign(key *ecdsa.PrivateKey, raw string) (string, error) {
	hash := sha256.Sum256([]byte(raw))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verify(text string, sign string, key *ecdsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	var s ecdsaSignature
	_, err = asn1.Unmarshal(sig, &s)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(text))
	if ecdsa.Verify(key, hash[:], s.R, s.S) {
		return nil
	} else {
		return ErrorInvalidSignature
	}
}

func compressAndBase64Encode(data []byte) string {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return base64urlEncode(b.Bytes())
}

func base64DecodeAndUncompress(data string) ([]byte, error) {
	raw, err := base64urlDecode(data)
	if err != nil {
		return nil, err
	}
	r, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(r)
}

func generateSig(privateKey string, obj map[string]string, genRawMethod func(map[string]string) string) (string, error) {
	key, err := readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	raw := genRawMethod(obj)
	signature, err := sign(key, raw)
	if err != nil {
		return "", err
	}
	obj["TLS.sig"] = signature

	text, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	return compressAndBase64Encode(text), nil
}

func GenerateUsersigWithExpire(privateKey string, appid int, identifier string, expire int64) (string, error) {
	obj := map[string]string{
		"TLS.account_type": "0",
		"TLS.identifier":   "" + identifier,
		"TLS.appid_at_3rd": "0",
		"TLS.sdk_appid":    strconv.Itoa(appid),
		"TLS.expire_after": strconv.FormatInt(expire, 10),
		"TLS.version":      "201610110000",
		"TLS.time":         strconv.FormatInt(time.Now().Unix(), 10),
	}
	return generateSig(privateKey, obj, generateSignContent)
}

func GenerateUsersig(privateKey string, appid int, identifier string) (string, error) {
	return GenerateUsersigWithExpire(privateKey, appid, identifier, 60*60*24*180)
}

func genSig(sdkappid int, identifier string, priKey string) (string, error) {
	return GenerateUsersigWithExpire(priKey, sdkappid, identifier, 60*60*24*180)
}

func GenerateUsersigWithUserbuf(privateKey string, appid int, identifier string, expire int64, userbuf []byte) (string, error) {
	obj := map[string]string{
		"TLS.account_type": "0",
		"TLS.identifier":   "" + identifier,
		"TLS.appid_at_3rd": "0",
		"TLS.sdk_appid":    strconv.Itoa(appid),
		"TLS.expire_after": strconv.FormatInt(expire, 10),
		"TLS.version":      "201610110000",
		"TLS.time":         strconv.FormatInt(time.Now().Unix(), 10),
		"TLS.userbuf":      base64.StdEncoding.EncodeToString(userbuf),
	}
	return generateSig(privateKey, obj, generateSignContentWithUserbuf)
}

func readAndVerifyUserSig(userSig string, appid int, identifier string, publicKey string, genRawMethod func(map[string]string) string) (map[string]string, error) {
	text, err := base64DecodeAndUncompress(userSig)
	if err != nil {
		return nil, err
	}
	obj := make(map[string]string)
	err = json.Unmarshal(text, &obj)
	if err != nil {
		return nil, err
	}
	if obj["TLS.identifier"] != identifier {
		return nil, ErrorIdentifierNotMatch
	}
	if obj["TLS.sdk_appid"] != strconv.Itoa(appid) {
		return nil, ErrorAppidNotMatch
	}
	createTime, err := strconv.ParseInt(obj["TLS.time"], 10, 64)
	if err != nil {
		return nil, err
	}
	expire, err := strconv.ParseInt(obj["TLS.expire_after"], 10, 64)
	if err != nil {
		return nil, err
	}
	if createTime+expire < time.Now().Unix() {
		return nil, ErrorExpired
	}
	key, err := readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	content := genRawMethod(obj)
	err = verify(content, obj["TLS.sig"], key)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func VerifyUsersig(publicKey string, usersig string, appid int, identifier string) error {
	_, err := readAndVerifyUserSig(usersig, appid, identifier, publicKey, generateSignContent)
	return err
}

func VerifyUsersigWithUserbuf(publicKey string, usersig string, appid int, identifier string) ([]byte, error) {
	obj, err := readAndVerifyUserSig(usersig, appid, identifier, publicKey, generateSignContentWithUserbuf)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(obj["TLS.userbuf"])
}

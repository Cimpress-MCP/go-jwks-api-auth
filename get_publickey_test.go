package jwks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Auth0Claims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

func TestGetPublicKey(t *testing.T) {
	// Mock resource server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["MIIDtTCCAp2gAwIBAgIJALEdCjaN9IYzMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMDEwMTkwMzMxWhcNMjYxMDA4MTkwMzMxWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlZylb92VpLV6T9Z1amA3omcsvtTcW+0ETeEqeIdFt/5fPL4y/295EILciO7/cxCbmjzXyI7onYVEt3qPleaZQ/MrZ+qndH+GOFPCQyYLUhPKuSz+WZERMP3KaGUOqMHA+4OeuVS9T081zYD0WSfa4B3xR/bTm+KC9NtJK6eYIAu1JUNN61hi7URDpMIrZyssS1mP/LnjPLXzF0Ll2weCfVptq0idcNWstMricvMGadhvpiZzNiYicCY7iNptRuknlvgMwKLDT5WH9Nnl+tST01mjobI19ShqDx042hPMKxH4A63JC7c/wjDGpeOIPCVEXvPVFy6/dwgtow7xfHkmsQIDAQABo4GnMIGkMB0GA1UdDgQWBBQqjWwGfzUks1XrwcFu1F7/Xhow6DB1BgNVHSMEbjBsgBQqjWwGfzUks1XrwcFu1F7/Xhow6KFJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJALEdCjaN9IYzMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAGtGNPB1J1TKaWUOnx2r+E7ZNMj2cD2UPubpLWTsOfHdPyl32NgrDaYtaW29vrki+p/xmZC4TX2EiG7pG4W1l3jUzWJdZCjxLpZNsyyTI8zPP1mMvwoOc50BhXRwEfYdj3v2o4USACNz8rIJCc6FiqzeVaEWDXhDp2z/50/6rtzxzvfbRaSD1YBuv+jI0dmcHZZCRDz+pb5n562D8xxanDcp+FLEOwP/I8xQUJFMBDNcmbP0AJRoAOWzfUzW1fL9UQGADymifzyMKtehIWzhlNxnuY0QkPj8FDl+ZGEaG8Y6An/BwIPGhUkyxGEmykpPjy1pauPwAamGoXRTdfZN8nw="],"n":"lZylb92VpLV6T9Z1amA3omcsvtTcW-0ETeEqeIdFt_5fPL4y_295EILciO7_cxCbmjzXyI7onYVEt3qPleaZQ_MrZ-qndH-GOFPCQyYLUhPKuSz-WZERMP3KaGUOqMHA-4OeuVS9T081zYD0WSfa4B3xR_bTm-KC9NtJK6eYIAu1JUNN61hi7URDpMIrZyssS1mP_LnjPLXzF0Ll2weCfVptq0idcNWstMricvMGadhvpiZzNiYicCY7iNptRuknlvgMwKLDT5WH9Nnl-tST01mjobI19ShqDx042hPMKxH4A63JC7c_wjDGpeOIPCVEXvPVFy6_dwgtow7xfHkmsQ","e":"AQAB","kid":"NDRBMzRGNTVFNzg3ODFEN0Y0MTFEMDg1REE0RDI4M0QyRDU4RTZGNg","x5t":"NDRBMzRGNTVFNzg3ODFEN0Y0MTFEMDg1REE0RDI4M0QyRDU4RTZGNg"}]}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Append trailing slash to server URL
	iss := fmt.Sprintf("%s/", ts.URL)
	aud := "https://api.example.com/"

	// Create JWT token
	now := time.Now()
	nowUnix := now.Unix()

	exp := now.Add(24 * time.Hour)
	expUnix := exp.Unix()

	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   "test@clients",
		"aud":   aud,
		"exp":   expUnix,
		"iat":   nowUnix,
		"scope": "",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "NDRBMzRGNTVFNzg3ODFEN0Y0MTFEMDg1REE0RDI4M0QyRDU4RTZGNg"

	// Test method
	pk, err := GetPublicKey(token, iss, aud)
	if err != nil {
		t.Errorf("GetPublicKey return error: %s", err)
	}

	// Verify public key
	PKFile, err := ioutil.ReadFile("test/pub.pem")
	if err != nil {
		t.Errorf("Public key read error: %s", err)
	}

	block, _ := pem.Decode(PKFile)
	wantPK, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	block, _ = pem.Decode(pk)
	gotPK, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(gotPK, wantPK) {
		t.Log("Mismatch in public key")
		t.FailNow()
	}
}

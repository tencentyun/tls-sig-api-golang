package TLSSigAPI

import (
	"bytes"
	"testing"
	"time"
)

const (
	privateKey = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHu8zGfpauyNJ0eMT8tq9FMARsYhcGPnd1Q/pkLPUMxeoAoGCCqGSM49
AwEHoUQDQgAEnVSjrROQGp3NV37boSqrxIo5Jkd/IZxWS5daT4gJTCzagSZG3FqT
PHykr4GXXzT+o/aJlvKVXi7ksthSHOUmqQ==
-----END EC PRIVATE KEY-----
`
	publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnVSjrROQGp3NV37boSqrxIo5Jkd/
IZxWS5daT4gJTCzagSZG3FqTPHykr4GXXzT+o/aJlvKVXi7ksthSHOUmqQ==
-----END PUBLIC KEY-----
`
)

func TestGenAndVerify(t *testing.T) {
	userSig, err := GenerateUsersig(privateKey, 1, "1")
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyUsersig(publicKey, userSig, 1, "1")
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyUsersig(publicKey, userSig, 1, "2")
	if err != ErrorIdentifierNotMatch {
		t.Fatal(err)
	}
	err = VerifyUsersig(publicKey, userSig, 2, "1")
	if err != ErrorAppidNotMatch {
		t.Fatal(err)
	}
}

func TestGenSigAndVerfiy(t *testing. T) {
	userSig, err := genSig(14000, "xiaojun", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyUsersig(publicKey, userSig, 14000, "xiaojun")
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenAndVerifyExpire(t *testing.T) {
	userSig, err := GenerateUsersigWithExpire(privateKey, 1, "1", 0)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Duration(time.Second))
	err = VerifyUsersig(publicKey, userSig, 1, "1")
	if err != ErrorExpired {
		t.Fatal(err)
	}
}

func TestGenAndVerifyUserBuf(t *testing.T) {
	buf := []byte{1, 2, 3}
	userSig, err := GenerateUsersigWithUserbuf(privateKey, 1, "1", 3600, buf)
	if err != nil {
		t.Fatal(err)
	}
	retBuf, err := VerifyUsersigWithUserbuf(publicKey, userSig, 1, "1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retBuf, buf) {
		t.Fatal("user buf not equal")
	}
	_, err = VerifyUsersigWithUserbuf(publicKey, userSig, 1, "2")
	if err != ErrorIdentifierNotMatch {
		t.Fatal(err)
	}
	_, err = VerifyUsersigWithUserbuf(publicKey, userSig, 2, "1")
	if err != ErrorAppidNotMatch {
		t.Fatal(err)
	}
}

func TestGenAndVerifyUserBufExpire(t *testing.T) {
	userSig, err := GenerateUsersigWithUserbuf(privateKey, 1, "1", 0, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Duration(time.Second))
	_, err = VerifyUsersigWithUserbuf(publicKey, userSig, 1, "1")
	if err != ErrorExpired {
		t.Fatal(err)
	}
}

func TestVerifyExistUserSig(t *testing.T) {
	sig := "eJxlz11PgzAYBeB7fkXDLUZbSqPd3dyHw4HJMoiZN01DO2mmUEsHlsX-bmQmI9nt*5ycN*fkAQD8LNne8qKoj5Vl1mnpgwnwoX9zQa2VYNwybMQVym*tjGR8b6UZMCQ0hHAcUUJWVu3VfwCNqBEHNtRfi3ofbuliN4s386WrVzOS9228Cnpxl96-LfkLdfN*lzwZXXYugjzLzEfjpnE5feavMv2iQbsVBG-WCeWHI4R5UYpcarVYl-hRo0x1gelGL636PI9HBOMQRQ8oGmkrTaPq6rwRIoJCSOHfUO-H*wVAW1nJ"
	pubkey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmAeEcipI6pcgR+egd5GM6F35XveJ
agHwdlx2f4PkTdGBzLOfMyU52lDF8ZFg00EE06QyQ7nB1GsZyXVKBkRGrg==
-----END PUBLIC KEY-----`
	err := VerifyUsersig(pubkey, sig, 1, "1")
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkGenerateUsersig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateUsersig(privateKey, 1, "1")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyUsersig(b *testing.B) {
	b.StopTimer()
	sig, err := GenerateUsersig(privateKey, 1, "1")
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err = VerifyUsersig(publicKey, sig, 1, "1")
		if err != nil {
			b.Fatal(err)
		}
	}
}

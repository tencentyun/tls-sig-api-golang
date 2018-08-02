package TLSSigAPI

import "testing"

func TestReadPKCS8PrivateKey(t *testing.T) {
	const text = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQge7zMZ+lq7I0nR4xP
y2r0UwBGxiFwY+d3VD+mQs9QzF6hRANCAASdVKOtE5Aanc1XftuhKqvEijkmR38h
nFZLl1pPiAlMLNqBJkbcWpM8fKSvgZdfNP6j9omW8pVeLuSy2FIc5Sap
-----END PRIVATE KEY-----
`
	key, err := readPrivateKey(text)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestReadECPrivateKey(t *testing.T) {
	const text = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC3W2j45mRQ2BqDTET2AuiSK4sPJJump68HLzFQgCcL4oAoGCCqGSM49
AwEHoUQDQgAE0YIf/QBsIeWN3MIoK2uLGICuYAus8MKaHkEEzTDHu+sfp7RHCGKW
xiDFmeD8IQd3ue9bjZ+i1fFrV4dflvtg3A==
-----END EC PRIVATE KEY-----
`
	key, err := readPrivateKey(text)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestReadPublicKey(t *testing.T) {
	const text = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP1ddui+JqlZnztysAZLNqc+rdpip
ExanYClZbXytFGEL/uJjfVC2pPoTBpKEU9V08BD+qZdD05J+KRxK794A7w==
-----END PUBLIC KEY-----
`
	key, err := readPublicKey(text)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestBadText(t *testing.T) {
	_, err := readPublicKey("asd")
	if err == nil {
		t.Fatal("should bee error")
	}

	_, err = readPrivateKey("asd")
	if err == nil {
		t.Fatal("should bee error")
	}
}

func TestOtherKey(t *testing.T) {
	_, err := readPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA3Zms7sWL668BhuN2C1UkcL2hiXpoZGD4nhielSLsrpKyccMj
sUaNh96wTXxWBR+lW5DVbs/auaQYChLEGL8VD7kEwGKqp/9rJ9QPGVHqRyb1HFy/
k5QjyKlpULFpy6LaiCrKJrruL82YK3W/hPm+l/PdT2ZsNJgnhg9xfMcGDKTWTewL
SAmyt4M8byOXmigsofsnWCMQsULqjQ8yD6NhRKIs/Tqg4gczYsbrzqpATQvRCGkI
IfW+RfTLnstaLq866amTa9GICvqYrI1PPi9qdtR4ju9bSZ+Iu3GAANd06y0AFNUF
gwS+aAlejtuWysJVGmLFCFRiiqidnODus/RgkQIDAQABAoIBAQCv2sxJj6tCFVd4
2/lJdP++GD6hAurk/a9OhusSHu0EfJXvgZRJkluufyIZ25nH5x0qVP2LOpewym/p
TosfuEPWflUu9x3GxAMdUEPLLB5m6JuLLm85hk3/Z7GTv7bdSxdxB8P0iFOMy/L+
Sir6M9b0byopYHZuJnD3CjpdcvNyA8MyY+jgAq6mzX4IfwqV/EKesiqxwXFB9Q0k
iiBV1XGni+NuBRHt4BU/4Org+RS025dMMHE4FM9cm7qMmaeXJ6O9cQkCIaYWIybm
rra1DS5e1+E2SdsyHK9Kc45730A2Db/eNoHuhc8BR5JG8Q4nRS7eZIh/1aTCVqyS
udnvuBWBAoGBAPocoa2oLiAIkducN3MUW16opFncr5H8miseDRleSR/xmWIWdQ9g
yYR75AA73KyiAV9PfgjwLIrbToWYejI/De//6TWSTFzavcqKTtTaE3zHF93rIg6S
781J7VU6G2Z0U7mfs9ArwQl0WwUKhBV1xO2G9eGkYGksukxkx05+HcZVAoGBAOLR
NhHXPu6BwVoZnxBL9WahTe+GfwSdjWJVuxKrBgbmwWJ1ys5UiVBkv9IB6Oq+iB7A
t1hOOhoW1jON9JiD7vjm5IYUOHVMx+ekXM/7Q6UDYqnFLgukBYf62suZ5MD7A2GR
4lHxv3JJ2S0Q3hN21siMM8t3Vh9J3s62Mq/gD9VNAoGBAOZgpRPeC8551lAgznpz
z82bLPeQ7S9dK2x327z4OgbwdUYCRYUKs9QSgestOJDTEMyH3iHBiGXGp8cqsbPC
nMXqRReRUEFfQt5jE0XAMZ8HjBZfVRlzgurnI3MTeNWgZNZgIjKnesGIqaY1D4Ds
352iaK2UyTFXf6qKUYMda7OZAoGBANJyeO+OvjY/sC2wDhTp1VSXH5+5M8sNf+wY
TU2h3yKyIgX/8t8EMq+j+xKYcQq1I8kc2ECXvHMOc0o8URDdgPHyEWCSDFxRlD1K
FE9o+7d0b6vDZtioI/Wp/C3iqQuhGt8Bo3KSkiYxfM7CkrqOjfRfmYMUQ5UeThuP
k3H5u9cVAoGBALABu3AurYqu7gN/HzdfdyxhacvMpDP02tm+OSuH87/i9f7oi6zr
cZ2EtfrJeQV8uDXtWn+SkrceReaVHnt6GuWsECsV8HJ0/bkw4G0+ibvM6sb/e0lm
fzFFWwTuYuMEElUhHecd1OJAbE/5KJWY1vBAjGrIYKsBDF46lO4a1PRD
-----END RSA PRIVATE KEY-----`)
	if err != ErrorInvalidKeyType {
		t.Fatal(err)
	}
	_, err = readPublicKey(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3UoakJ205m2VIvxSWIwA
vy3doqotRvdsz5Z67bfm0d2tDae3jHpJUaoQ2wR3jDGUdf1srcq66Z53amMT9LEw
WpVdZcTcMERA8DguwAoUwaOJiivG/IcUXK2r9HaA7/dt6V/OUT8sOWOcEbOB18vs
EE3lxVccz7SOs//IeFUCCwnbx5YwAHbXz0b4VUBH8PtWGvE5nhuiexmTMAdPiLkn
vSEzdQQshSqd3n1H0gHb+YwQcAbU6x7Fv4OggmkmidETeBJQvUzuSR4FLRHqgugx
WHu3ctVnDXITNH/ZyDBpekgkHTiLC3SGJB3iao5Az+0ndEYz+LEZqgDHuNrmY9gn
gQIDAQAB
-----END PUBLIC KEY-----`)
	if err != ErrorInvalidKeyType {
		t.Fatal(err)
	}

}

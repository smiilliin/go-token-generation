package gotokengeneration

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func GetGeneration(db *sql.DB, id string) (int, error) {
	rows, err := db.Query("SELECT gen FROM generation WHERE id=?", id)

	if err != nil {
		return 0, err
	}

	defer rows.Close()

	if !rows.Next() {
		_, err = db.Exec("INSERT INTO generation VALUES(?, 0)", id)

		if err != nil {
			return 0, err
		}

		return 0, nil
	}

	var gen int

	if err := rows.Scan(&gen); err != nil {
		return 0, err
	}

	return gen, nil
}

func AddGeneration(db *sql.DB, id string) error {
	_, err := db.Exec("UPDATE generation SET gen=gen+1 WHERE id=?", id)

	if err != nil {
		return err
	}

	return nil
}

type Token struct {
	Type    string `json:"type"`
	Expires int64  `json:"expires"`
}
type RefreshToken struct {
	Token
	ID         string `json:"id"`
	Generation int    `json:"generation"`
	UUID       string `json:"uuid"`
}
type AccessToken struct {
	Token
	ID   string `json:"id"`
	UUID string `json:"uuid"`
}

func CheckGeneration(db *sql.DB, token *RefreshToken) bool {
	gen, err := GetGeneration(db, token.ID)

	if err != nil {
		return false
	}

	if gen > token.Generation {
		return false
	}

	return true
}

func CreateRefreshToken(db *sql.DB, id string, duration time.Duration) (*RefreshToken, error) {
	gen, err := GetGeneration(db, id)
	if err != nil {
		return nil, err
	}

	return &RefreshToken{Token: Token{Type: "refresh", Expires: time.Now().Add(duration).UnixMilli()},
		ID: id, Generation: gen, UUID: uuid.NewString()}, nil
}

func UpdateRefreshToken(db *sql.DB, token *RefreshToken, days int) error {
	if !CheckGeneration(db, token) {
		return fmt.Errorf("generation checking failed")
	}

	token.Expires = time.Now().AddDate(0, 0, days).UnixMilli()
	return nil
}

func CreateAccessToken(db *sql.DB, token *RefreshToken, duration time.Duration) (*AccessToken, error) {
	if !CheckGeneration(db, token) {
		return nil, fmt.Errorf("generation checking failed")
	}

	accessToken := AccessToken{Token: Token{Type: "access", Expires: time.Now().Add(duration).UnixMilli()},
		ID: token.ID, UUID: uuid.NewString()}

	return &accessToken, nil
}

func RefreshTokenParse(tokenString string, hmacKey []byte) (*RefreshToken, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return hmacKey, nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, fmt.Errorf("parsing error")
	}

	refreshToken := RefreshToken{Token: Token{Type: claims["type"].(string), Expires: int64(claims["expires"].(float64))},
		ID: claims["id"].(string), Generation: int(claims["generation"].(float64)), UUID: claims["uuid"].(string)}

	if refreshToken.Expires < time.Now().UnixMilli() {
		return nil, fmt.Errorf("expired")
	}
	if refreshToken.Type != "refresh" {
		return nil, fmt.Errorf("type is not matched")
	}

	return &refreshToken, nil
}

func AccessTokenParse(tokenString string, hmacKey []byte) (*AccessToken, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return hmacKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, fmt.Errorf("parsing error")
	}

	accessToken := AccessToken{Token: Token{Type: claims["type"].(string), Expires: int64(claims["expires"].(float64))},
		ID: claims["id"].(string), UUID: claims["uuid"].(string)}

	if accessToken.Expires < time.Now().UnixMilli() {
		return nil, fmt.Errorf("expired")
	}
	if accessToken.Type != "access" {
		return nil, fmt.Errorf("type is not matched")
	}

	return &accessToken, nil
}

func AccessTokenToString(accessToken *AccessToken, hmacKey []byte) (string, error) {
	claims := jwt.MapClaims{
		"type":    accessToken.Type,
		"expires": accessToken.Expires,
		"id":      accessToken.ID,
		"uuid":    accessToken.UUID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(hmacKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func RefreshTokenToString(refreshToken *RefreshToken, hmacKey []byte) (string, error) {
	claims := jwt.MapClaims{
		"type":       refreshToken.Type,
		"expires":    refreshToken.Expires,
		"id":         refreshToken.ID,
		"generation": refreshToken.Generation,
		"uuid":       refreshToken.UUID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(hmacKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

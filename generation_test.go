package gotokengeneration

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

func TestGetGeneration(t *testing.T) {
	db, id, err := getEssential()

	if err != nil {
		t.Fatal(err)
	}

	_, err = GetGeneration(db, id)

	if err != nil {
		t.Fatal(err)
	}
}

func TestAddGeneration(t *testing.T) {
	db, id, err := getEssential()

	if err != nil {
		t.Fatal(err)
	}

	oldGeneration, err := GetGeneration(db, id)

	if err != nil {
		t.Fatal(err)
	}
	err = AddGeneration(db, id)

	if err != nil {
		t.Fatal(err)
	}

	newGeneration, err := GetGeneration(db, id)

	if err != nil {
		t.Fatal(err)
	}

	if newGeneration-1 != oldGeneration {
		t.Fatalf("generation is not added")
	}
}

func TestCreateRefreshToken(t *testing.T) {
	db, id, err := getEssential()

	if err != nil {
		t.Fatal(err)
	}

	hmacKey, err := getHmacKey()

	if err != nil {
		t.Fatal(err)
	}

	token, err := CreateRefreshToken(db, id, 30*24*time.Hour)

	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := RefreshTokenToString(token, hmacKey)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(tokenString)

	parsedToken, err := RefreshTokenParse(tokenString, hmacKey)

	if err != nil {
		t.Fatal(err)
	}

	if token.UUID != parsedToken.UUID {
		t.Fatalf("uuid is not matched")
	}

	fmt.Println(parsedToken.UUID)
}
func TestCreateAccessToken(t *testing.T) {
	db, id, err := getEssential()

	if err != nil {
		t.Fatal(err)
	}

	hmacKey, err := getHmacKey()

	if err != nil {
		t.Fatal(err)
	}

	refreshToken, err := CreateRefreshToken(db, id, 30*24*time.Hour)

	if err != nil {
		t.Fatal(err)
	}

	token, err := CreateAccessToken(db, refreshToken, 24*time.Minute)

	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := AccessTokenToString(token, hmacKey)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(tokenString)

	parsedToken, err := AccessTokenParse(tokenString, hmacKey)

	if err != nil {
		t.Fatal(err)
	}

	if token.UUID != parsedToken.UUID {
		t.Fatalf("uuid is not matched")
	}

	fmt.Println(parsedToken.UUID)
}
func TestInvalidParse(t *testing.T) {
	db, id, err := getEssential()

	if err != nil {
		t.Fatal(err)
	}

	refreshToken, err := CreateRefreshToken(db, id, 30*24*time.Hour)

	if err != nil {
		t.Fatal(err)
	}

	hmacKey, err := getHmacKey()

	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := RefreshTokenToString(refreshToken, []byte("wrongkeyyy"))

	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}
	_, err = RefreshTokenParse(tokenString, hmacKey)

	if err == nil {
		t.Fatalf("just passed the wrong token")
	}
}

func getDB() (*sql.DB, error) {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbDatabase := os.Getenv("DB_DATABASE")

	dbDSN := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/%s", dbUser, dbPassword, dbDatabase)
	db, err := sql.Open("mysql", dbDSN)

	if err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(3)
	db.SetMaxOpenConns(6)

	return db, nil
}
func getEssential() (*sql.DB, string, error) {
	err := godotenv.Load()

	if err != nil {
		return nil, "", err
	}

	db, err := getDB()
	if err != nil {
		return nil, "", err
	}
	id := os.Getenv("TEST_ID")

	return db, id, nil
}

func getHmacKey() ([]byte, error) {
	file, err := os.Open("../.hmacKey")

	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()

	if err != nil {
		return nil, err
	}

	fileData := make([]byte, info.Size())
	_, err = file.Read(fileData)

	if err != nil {
		return nil, err
	}

	decoded := make([]byte, hex.DecodedLen(len(fileData)))
	_, err = hex.Decode(decoded, fileData)

	if err != nil {
		return nil, err
	}

	return decoded, nil
}

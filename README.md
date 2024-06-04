# Go-Token-generation

Disable the refresh token with golang

## Explanation

https://velog.io/@smiilliin/token-generation-구조

## Usage

### CreateRefreshToken

Create new refresh token

```go
refreshToken, err := CreateRefreshToken(db, id, 30*24*time.Hour)
```

### CreateAccessToken

Create new access token

```go
accessToken, err := CreateAccessToken(db, refreshToken, 24*time.Minute)
```

### RefreshTokenToString

Convert refresh token to string

```go
tokenString, err := RefreshTokenToString(token, hmacKey)
```

### RefreshTokenParse

Parse refresh token string

```go
parsedToken, err := RefreshTokenParse(tokenString, hmacKey)
```

### UpdateRefreshToken

Parse refresh token string

```go
parsedToken, err := UpdateRefreshToken(db, refreshToken, 30*24*time.Hour)
```

### AccessTokenToString

Convert access token to string

```go
tokenString, err := AccessTokenToString(token, hmacKey)
```

### AccessTokenParse

Parse refresh token string

```go
parsedToken, err := AccessTokenParse(tokenString, hmacKey)
```

## Get

Get go-token-generation package

```bash
go mod get github.com/smiilliin/go-token-generation
```

## Test

Start token-generation tests(required "../.hmackey" file)

```bash
go test
```

# Go JWT Implementation

Json Web Token stands is used to check if a user is authorized or not via creating a JWT token and sending it as a Cookie. This Cookie will be sent/recieved by all the requests now the server make.

# How it works in Go

1. After checking the password, if the user is authorized or not. 

```go
	// verify the user by checking password
	expectedPassword, ok := users[credentials.Username]
	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
```

2. We will create a JWT token which takes *Signing Method* and `Claims` struct as input.  

```go

	expirationTime := time.Now().Add(5 * time.Minute)

  // claims struct contains the expirationTime and other information about the token
	claims := &Claims{
		Username: credentials.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    credentials.Username,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// this gives unsigned jwt token with claims and algo name
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
```

3. After the token is created. It is yet to be signed to be sent to the client as a Cookie. So then we sign it with the key.

NOTE: The key is the part that makes the jwt token secure.

```go
	// this signs the jwt token returning complete and signed jwt token
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
```

4. Then we send the token as a cookie to the client and it will be sent/recieved with each request.

```go

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
```

### Extras

For more clarity, you can learn how JWT works in Go

. https://jwt.io/introduction/

you can check the code for more clarity

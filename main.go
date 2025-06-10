package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	googleClientID     = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
)

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleInfoURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
)

const (
	redirectURI      = "http://localhost:8000/oauth/callback"
	scopes           = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
	oauthStateString = "random-string"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("GET /login", loginHandler)
	mux.HandleFunc("GET /oauth/callback", callbackHandler)
	fmt.Println("Server started at http://localhost:8000")

	log.Fatal(http.ListenAndServe(":8000", mux))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	html := `
	<html>
		<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
			<h1>OAuth2 Demo with Go</h1>
			<p>Click the link below to log in with your Google account.</p>
			<a href="/login" style="font-size: 20px; padding: 10px 20px; background-color: #4285F4; color: white; text-decoration: none; border-radius: 5px;">Login with Google</a>
		</body>
	</html>`
	fmt.Fprint(w, html)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		googleAuthURL,
		url.QueryEscape(googleClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopes),
		url.QueryEscape(oauthStateString),
	)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// --- Step 2: Handle the callback and verify the state ---
	state := r.URL.Query().Get("state")
	if state != oauthStateString {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		fmt.Println("Error: invalid state parameter")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		fmt.Println("Error: Authorization code not found")
		return
	}

	// --- Step 3: Exchange the Authorization Code for an Access Token ---
	accessToken, err := exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		fmt.Printf("Error exchanging code for token: %v\n", err)
		return
	}

	// --- Step 5: Making Authenticated API Calls ---
	userInfo, err := getUserInfo(accessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		fmt.Printf("Error getting user info: %v\n", err)
		return
	}

	// Display the user's information
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>Welcome, %s!</h1>", userInfo.Name)
	fmt.Fprintf(w, "<p>Email: %s</p>", userInfo.Email)
	fmt.Fprintf(w, "<img src='%s' alt='Profile Picture' style='border-radius: 50%%;'>", userInfo.Picture)
	fmt.Fprintf(w, "<hr><pre>%+v</pre>", userInfo)
}

// exchangeCodeForToken performs the token exchange (Phase 2, Step 3)
func exchangeCodeForToken(code string) (string, error) {
	// Prepare the data for the POST request
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", googleClientID)
	data.Set("client_secret", googleClientSecret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	// Create the request
	req, err := http.NewRequest("POST", googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status: %s, body: %s", resp.Status, string(body))
	}

	// Parse the token from the response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	return tokenResponse.AccessToken, nil
}

// getUserInfo fetches user profile data from Google (Phase 2, Step 5)
func getUserInfo(accessToken string) (*UserInfo, error) {
	// Create the request
	req, err := http.NewRequest("GET", googleInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	// Add the Authorization header with the access token
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// Send the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send user info request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status: %s, body: %s", resp.Status, string(body))
	}

	// Parse the user info from the response
	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info response: %w", err)
	}

	return &userInfo, nil
}

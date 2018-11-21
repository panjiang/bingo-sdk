package oauth2

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/panjiang/golog"
)

// Config 777bingo平台OAuth2.0参数配置
type Config struct {
	PlatformHost string `json:"platform_host"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
}

// GetTokenURL 获取Token的URL
func (c *Config) GetTokenURL() string {
	return c.PlatformHost + "/oauth2/v1/token"
}

// GetProfileURL 获取个人数据的URL
func (c *Config) GetProfileURL(accessToken string) string {
	return c.PlatformHost + fmt.Sprintf("/oauth2/v1/profile?access_token=%s", accessToken)
}

// GetWalletURL 获取钱包数据的URL
func (c *Config) GetWalletURL(accessToken string) string {
	return c.PlatformHost + fmt.Sprintf("/oauth2/v1/wallet?access_token=%s&type=qtum", accessToken)
}

// Error 错误数据
type Error struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// Message 错误内容
func (e *Error) Message() string {
	return fmt.Sprintf("%s: %s", e.Error, e.Description)
}

// Token 令牌数据
type Token struct {
	*Error
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// Profile 个人信息
type Profile struct {
	*Error
	Code     int    `json:"code"`
	ID       int64  `json:"id"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

// Wallet 钱包数据
type Wallet struct {
	*Error
	Code    int     `json:"code"`
	Address string  `json:"address"`
	Balance float64 `json:"balance"`
}

func httpGet(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	log.Debugf("body: %s", body)

	// 错误
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", res.Status, body)
	}

	return body, nil
}

// GetToken 获取Token
func GetToken(code string, conf *Config) (*Token, error) {
	// Request token with code and client_secret
	search := url.Values{}
	search.Set("grant_type", "authorization_code")
	search.Set("code", code)
	search.Set("redirect_uri", conf.RedirectURI) // 不会实际调整, 验证用

	client := &http.Client{Timeout: 3 * time.Second}
	hreq, err := http.NewRequest("POST", conf.GetTokenURL(), strings.NewReader(search.Encode()))
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.SetBasicAuth(conf.ClientID, conf.ClientSecret)
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}

	// 解析返回
	decoder := json.NewDecoder(resp.Body)
	var token Token
	if err := decoder.Decode(&token); err != nil {
		return nil, err
	}

	if token.Error != nil {
		return nil, fmt.Errorf("Get token failed: %s", token.Error.Message())
	}

	return &token, nil
}

// GetProfile 获取个人信息
func GetProfile(conf *Config, accessToken string) (*Profile, error) {
	body, err := httpGet(conf.GetProfileURL(accessToken))
	if err != nil {
		return nil, err
	}

	var profile Profile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, err
	}

	if profile.Error != nil {
		return nil, fmt.Errorf("Get profile failed: %s", profile.Error.Message())
	}

	return &profile, nil
}

// GetWallet 获取钱包信息
func GetWallet(conf *Config, accessToken string) (*Wallet, error) {
	body, err := httpGet(conf.GetWalletURL(accessToken))
	if err != nil {
		return nil, err
	}

	var wallet Wallet
	if err := json.Unmarshal(body, &wallet); err != nil {
		return nil, err
	}

	if wallet.Error != nil {
		return nil, fmt.Errorf("Get wallet failed: %s", wallet.Error.Message())
	}

	return &wallet, nil
}

func init() {
	// 注册新gob类型，以便session解析
	gob.Register(new(Token))
}

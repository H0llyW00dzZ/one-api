package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"one-api/common"
	"one-api/model"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type wechatLoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

// Trusted domains list
var trustedDomains = map[string]bool{
	"api.wechat.com":           true,
	"api.weixin.qq.com":        true,
	common.WeChatServerAddress: true,
	// Add other trusted domains here
}

func isTrustedURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	// Check against the common address at runtime
	if parsedURL.Host == url.Parse(common.WeChatServerAddress).Host {
		return true
	}
	_, trusted := trustedDomains[parsedURL.Host]
	return trusted
}

func getWeChatIdByCode(code string) (string, error) {
	// Validate the code - this is a simple example, you'll need to adjust the regex to fit your actual code format
	matched, err := regexp.MatchString(`^[a-zA-Z0-9]{10,}$`, code) // Fixed missing quote
	if err != nil {
		// handle regex error
		return "", err
	}
	if !matched {
		return "", errors.New("invalid code format")
	}

	// Use net/url to build the query safely
	baseUrl, err := url.Parse(common.WeChatServerAddress)
	if err != nil || !isTrustedURL(baseUrl.String()) {
		return "", errors.New("untrusted server address")
	}
	// Ensure the base URL is a trusted endpoint to prevent SSRF
	// You might want to check it against a list of allowed domains/URLs

	params := url.Values{}
	params.Add("code", code)
	baseUrl.Path += "/api/wechat/user"
	baseUrl.RawQuery = params.Encode()

	// For CSRF protection, ensure that any state-changing operations are only
	// performed if a valid CSRF token is included in the request.
	// This is more relevant for POST/PUT/DELETE requests.

	req, err := http.NewRequest("GET", baseUrl.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", common.WeChatServerToken) // Ensure this token is securely managed
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()
	var res wechatLoginResponse
	if err = json.NewDecoder(httpResponse.Body).Decode(&res); err != nil {
		return "", err
	}
	if !res.Success {
		return "", errors.New(res.Message)
	}
	if res.Data == "" {
		return "", errors.New("验证码错误或已过期")
	}
	return res.Data, nil
}

func WeChatAuth(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员未开启通过微信登录以及注册",
			"success": false,
		})
		return
	}
	code := c.Query("code")
	wechatId, err := getWeChatIdByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	user := model.User{
		WeChatId: wechatId,
	}
	if model.IsWeChatIdAlreadyTaken(wechatId) {
		err := user.FillUserByWeChatId()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	} else {
		if common.RegisterEnabled {
			user.Username = "wechat_" + strconv.Itoa(model.GetMaxUserId()+1)
			user.DisplayName = "WeChat User"
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled

			if err := user.Insert(0); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				return
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
		}
	}

	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}
	setupLogin(&user, c)
}

func WeChatBind(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员未开启通过微信登录以及注册",
			"success": false,
		})
		return
	}
	code := c.Query("code")
	wechatId, err := getWeChatIdByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	if model.IsWeChatIdAlreadyTaken(wechatId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该微信账号已被绑定",
		})
		return
	}
	id := c.GetInt("id")
	user := model.User{
		Id: id,
	}
	err = user.FillUserById()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user.WeChatId = wechatId
	err = user.Update(false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

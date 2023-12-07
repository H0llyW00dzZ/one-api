// Gin + IO By H0llyW00dzZ
package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"one-api/common"
	"one-api/model"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type wechatLoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

// Validate the WeChat server address and return the validated URL.
func ValidateWeChatServerAddress(address string) (*url.URL, error) {
	if address == "" {
		return nil, errors.New("WeChat server address is not set")
	}
	parsedUrl, err := url.ParseRequestURI(address)
	if err != nil {
		return nil, fmt.Errorf("WeChat server address is invalid: %v", err)
	}

	// Ensure that the address is HTTPS to avoid MITM attacks.
	if parsedUrl.Scheme != "https" {
		return nil, errors.New("WeChat server address must use HTTPS")
	}

	// Whitelisting domains to avoid SSRF Attacks.
	allowedDomains := []string{"google.com", "go.dev"} // only need implement this line
	isValidDomain := false
	for _, domain := range allowedDomains {
		if parsedUrl.Host == domain {
			isValidDomain = true
			break
		}
	}
	if !isValidDomain {
		return nil, fmt.Errorf("WeChat server address is not in the list of allowed domains")
	}

	return parsedUrl, nil
}

func getWeChatIdByCode(code string) (string, error) {
	if code == "" {
		return "", errors.New("invalid argument: code is empty")
	}

	// Validate the WeChat server address before using it.
	// so Attacker can't using SSRF to attack our server or using our server to attack other server.
	validatedUrl, err := ValidateWeChatServerAddress(common.WeChatServerAddress)
	if err != nil {
		return "", fmt.Errorf("WeChat server address validation failed: %v", err)
	}

	// Append only the path to the baseUrl
	validatedUrl.Path += "/api/wechat/user"

	params := url.Values{}
	params.Add("code", code)
	validatedUrl.RawQuery = params.Encode()

	req, err := http.NewRequest("GET", validatedUrl.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create new request: %v", err)
	}
	req.Header.Set("Authorization", common.WeChatServerToken)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request to WeChat server failed: %v", err)
	}
	defer httpResponse.Body.Close()

	// Check if the status code indicates success
	if httpResponse.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status code: %d", httpResponse.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Check the Content-Type to be sure we received JSON
	contentType := httpResponse.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return "", fmt.Errorf("expected JSON response but got Content-Type: %s", contentType)
	}

	// Attempt to unmarshal the response body into the expected JSON structure
	var res wechatLoginResponse
	err = json.Unmarshal(bodyBytes, &res)
	if err != nil {
		return "", fmt.Errorf("failed to decode JSON response: %v", err)
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
				"message": err.Error(),
				"success": false,
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

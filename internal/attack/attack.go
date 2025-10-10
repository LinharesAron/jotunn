package attack

import (
	"io"
	"net/http"
	"strings"

	"github.com/LinharesAron/jotunn/internal/config"
	"github.com/LinharesAron/jotunn/internal/types"
	"github.com/LinharesAron/jotunn/internal/utils"
)

func ExecuteAttempt(client *http.Client, cfg *config.AttackConfig, attempt types.Attempt) (bool, int, error) {

	values := map[string]string{
		"^USER^": attempt.Username,
		"^PASS^": attempt.Password,
	}
	var (
		cookies    string
		statusCode int
		csrfToken  string
		err        error
	)

	if cfg.CSRFField != "" {
		statusCode, csrfToken, cookies, err = utils.RetrieveCSRFToken(client, cfg.CSRFField, cfg.CSRFSourceURL)
		if err != nil {
			return false, statusCode, err
		}
		values["^CSRF^"] = csrfToken
	}

	payload, err := utils.SafeReplacePayload(cfg.Payload, values)
	if err != nil {
		return false, -1, err
	}

	var req *http.Request

	if strings.ToUpper(cfg.Method) == "GET" {
		urlWithQuery := cfg.URL + "?" + payload
		req, err = http.NewRequest(cfg.Method, urlWithQuery, nil)
	} else {
		req, err = http.NewRequest(cfg.Method, cfg.URL, strings.NewReader(payload))
	}

	if err != nil {
		return false, -1, err
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, -1, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, -1, err
	}

	body := string(bodyBytes)
	statusCode = resp.StatusCode

	valid, err := isValidResponse(cfg, resp.Header, body, statusCode)
	if err != nil {
		return false, statusCode, err
	}
	return valid, statusCode, nil
}

func isValidStatusCode(statusCode int) bool {
	return statusCode >= 200 && statusCode < 400
}

func isValidResponse(cfg *config.AttackConfig, header http.Header, body string, statusCode int) (bool, error) {
	keyword := cfg.Keyword()
	containsKeywordBody := strings.Contains(body, keyword)

	containsKeywordHeader := false
	for k, values := range header {
		if strings.Contains(k, keyword) {
			containsKeywordHeader = true
			break
		}

		for _, v := range values {
			if strings.Contains(v, keyword) {
				containsKeywordHeader = true
				break
			}
		}

		if containsKeywordHeader {
			break
		}
	}

	validStatusCode := isValidStatusCode(statusCode)
	if !validStatusCode {
		return false, &InvalidStatusCode{statusCode}
	}

	if cfg.IsSuccessKeyword {
		return containsKeywordBody || containsKeywordHeader, nil
	}

	if containsKeywordBody || containsKeywordHeader {
		return false, nil
	}

	return true, nil
}

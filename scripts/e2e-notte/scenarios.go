package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// values are the stand-ins and real values of one run. All are test values,
// new on every run except the test card numbers.
type values struct {
	cardStandIn, cardReal     string
	cvcStandIn, cvcReal       string
	userStandIn, userReal     string
	passStandIn, passReal     string
	jsonStandIn, jsonReal     string
	totpStandIn               string
	totpSecret                []byte
	bearerStandIn, bearerReal string
	keyStandIn, keyReal       string
	maskStandIn, maskReal     string
}

func newValues() (values, error) {
	secret, err := randomBytes(20)
	if err != nil {
		return values{}, err
	}
	r := func() string { return randomHex(6) }
	v := values{
		// Stripe test cards: the stand-in is the one agents know, the real
		// value another test card.
		cardStandIn: "4242424242424242", cardReal: "4000056655665556",
		cvcStandIn: "tok_cvc_" + r(), cvcReal: "737",
		userStandIn: "tok_user_" + r(), userReal: "e2e+" + r() + "@example.com",
		// Characters a form body must escape.
		passStandIn: "tok_pass_" + r(), passReal: "pw " + r() + " &=+%é",
		// Characters a JSON string must escape, and some it may.
		jsonStandIn: "tok_json_" + r(), jsonReal: `pw"\` + r() + ` é<&>`,
		totpStandIn: "tok_totp_" + r(), totpSecret: secret,
		bearerStandIn: "tok_bearer_" + r(), bearerReal: "bearer-" + r(),
		// Characters a query string must escape.
		keyStandIn: "tok_key_" + r(), keyReal: "key/" + r() + "+=&?",
		maskStandIn: "tok_mask_" + r(), maskReal: "real_mask_" + r(),
	}
	return v, nil
}

// scenarioIDs is the order of the summary.
var scenarioIDs = []string{
	"card", "password-form", "password-json", "totp", "bearer-token",
	"api-key-query", "masking", "not-allowlisted",
}

type scenario struct {
	id  string
	run func(ctx context.Context) error
}

// swapScenarios run in the session of the http resolver proxy, with
// response masking off, against the third-party echo host: the page reads
// what the host received in its echo.
func (e *e2e) swapScenarios() []scenario {
	return []scenario{
		{"card", e.card},
		{"password-form", e.passwordForm},
		{"totp", e.totpCode},
		{"bearer-token", e.bearerToken},
		{"api-key-query", e.apiKeyQuery},
		{"not-allowlisted", e.notAllowlisted},
	}
}

// maskScenarios run in the session of the file resolver proxy, with
// response masking on, against the capture server this test runs: it reads
// what arrived upstream directly, not through the page.
func (e *e2e) maskScenarios() []scenario {
	return []scenario{
		{"password-json", e.passwordJSON},
		{"masking", e.masking},
	}
}

// echo is the part of a postman-echo answer the scenarios read.
type echo struct {
	Args    map[string]any `json:"args"`
	Form    map[string]any `json:"form"`
	Headers map[string]any `json:"headers"`
}

func (e *e2e) echoFetch(ctx context.Context, req fetchRequest) (echo, string, error) {
	status, body, err := e.api.fetch(ctx, e.swapSession, req)
	if err != nil {
		return echo{}, "", err
	}
	if status != http.StatusOK {
		return echo{}, body, fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL, status, truncate(body, 300))
	}
	var out echo
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return echo{}, body, fmt.Errorf("%s %s did not answer an echo: %s", req.Method, req.URL, truncate(body, 300))
	}
	return out, body, nil
}

// expect compares a field the destination received with the real value.
func expect(field string, got any, real, standIn string) error {
	s, _ := got.(string)
	switch {
	case got == nil:
		return fmt.Errorf("%s is missing", field)
	case s == real:
		return nil
	case s == standIn:
		return fmt.Errorf("%s is still the stand-in", field)
	default:
		return fmt.Errorf("%s is %q, not the real value", field, s)
	}
}

// noStandIns fails when text still holds one of the stand-ins.
func noStandIns(where, text string, standIns ...string) error {
	for _, s := range standIns {
		if strings.Contains(text, s) {
			return fmt.Errorf("%s still holds the stand-in %q", where, s)
		}
	}
	return nil
}

func (e *e2e) swapURL(path string) string { return "https://" + e.cfg.swapHost + path }

// card: a card number and CVC in a form-urlencoded POST body.
func (e *e2e) card(ctx context.Context) error {
	v := e.values
	got, body, err := e.echoFetch(ctx, fetchRequest{URL: e.swapURL("/post"), Method: http.MethodPost,
		Form: map[string]string{"card_number": v.cardStandIn, "cvc": v.cvcStandIn, "exp": "12/34"}})
	if err != nil {
		return err
	}
	return errors.Join(
		expect("form.card_number", got.Form["card_number"], v.cardReal, v.cardStandIn),
		expect("form.cvc", got.Form["cvc"], v.cvcReal, v.cvcStandIn),
		noStandIns("the echo", body, v.cardStandIn, v.cvcStandIn),
	)
}

// passwordForm: a username and password in a form-urlencoded login POST.
func (e *e2e) passwordForm(ctx context.Context) error {
	v := e.values
	got, body, err := e.echoFetch(ctx, fetchRequest{URL: e.swapURL("/post"), Method: http.MethodPost,
		Form: map[string]string{"username": v.userStandIn, "password": v.passStandIn}})
	if err != nil {
		return err
	}
	return errors.Join(
		expect("form.username", got.Form["username"], v.userReal, v.userStandIn),
		expect("form.password", got.Form["password"], v.passReal, v.passStandIn),
		noStandIns("the echo", body, v.userStandIn, v.passStandIn),
	)
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

// totpCode: a 2FA code whose stand-in is stable and whose real value the
// http resolver computes when the proxy asks for it (its cache is off).
func (e *e2e) totpCode(ctx context.Context) error {
	v := e.values
	from := time.Now()
	got, _, err := e.echoFetch(ctx, fetchRequest{URL: e.swapURL("/post"), Method: http.MethodPost,
		Form: map[string]string{"otp": v.totpStandIn}})
	to := time.Now()
	if err != nil {
		return err
	}
	code, _ := got.Form["otp"].(string)
	switch {
	case code == v.totpStandIn:
		return errors.New("form.otp is still the stand-in")
	case !sixDigits.MatchString(code):
		return fmt.Errorf("form.otp is %q, not a 6-digit code", code)
	case !totpMatches(v.totpSecret, code, from, to):
		return fmt.Errorf("form.otp %s is not the TOTP of %s to %s, give or take one step",
			code, from.UTC().Format(time.TimeOnly), to.UTC().Format(time.TimeOnly))
	case !e.detokenizer.asked(e.cfg.swapHost, v.totpStandIn):
		return errors.New("the resolver was never asked for the TOTP stand-in")
	}
	return nil
}

// bearerToken: a token in an Authorization: Bearer header.
func (e *e2e) bearerToken(ctx context.Context) error {
	v := e.values
	got, _, err := e.echoFetch(ctx, fetchRequest{URL: e.swapURL("/get"), Method: http.MethodGet,
		Headers: map[string]string{"Authorization": "Bearer " + v.bearerStandIn}})
	if err != nil {
		return err
	}
	return expect("headers.authorization", got.Headers["authorization"], "Bearer "+v.bearerReal, "Bearer "+v.bearerStandIn)
}

// apiKeyQuery: an API key in the query string.
func (e *e2e) apiKeyQuery(ctx context.Context) error {
	v := e.values
	got, _, err := e.echoFetch(ctx, fetchRequest{URL: e.swapURL("/get?page=1&api_key=" + url.QueryEscape(v.keyStandIn)), Method: http.MethodGet})
	if err != nil {
		return err
	}
	return expect("args.api_key", got.Args["api_key"], v.keyReal, v.keyStandIn)
}

// notAllowlisted: a host outside the session's secret proxy hosts gets
// the stand-ins unchanged.
func (e *e2e) notAllowlisted(ctx context.Context) error {
	v := e.values
	base := "https://" + e.cfg.controlHost
	if err := e.api.gotoURL(ctx, e.swapSession, base+"/get"); err != nil {
		return err
	}
	status, body, err := e.api.fetch(ctx, e.swapSession, fetchRequest{Method: http.MethodPost,
		URL:  base + "/anything?api_key=" + url.QueryEscape(v.keyStandIn),
		Form: map[string]string{"card_number": v.cardStandIn, "password": v.passStandIn}})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("%s returned %d: %s", e.cfg.controlHost, status, truncate(body, 300))
	}
	for _, pair := range [][2]string{{v.keyStandIn, v.keyReal}, {v.cardStandIn, v.cardReal}, {v.passStandIn, v.passReal}} {
		if !strings.Contains(body, pair[0]) {
			return fmt.Errorf("the %s echo does not hold the stand-in %q: %s", e.cfg.controlHost, pair[0], truncate(body, 300))
		}
	}
	if strings.Contains(body, v.cardReal) || strings.Contains(body, v.keyReal) {
		return fmt.Errorf("%s received a real value", e.cfg.controlHost)
	}
	if e.detokenizer.asked(e.cfg.controlHost, v.keyStandIn) {
		return fmt.Errorf("the resolver was asked for a value for %s", e.cfg.controlHost)
	}
	return nil
}

func (e *e2e) captureURL(name string) string {
	return "https://" + e.captureHost + capturePrefix + name
}

// ngrokSkipHeader keeps ngrok's browser warning page off the capture
// requests.
const ngrokSkipHeader = "ngrok-skip-browser-warning"

// captureJSON posts body as JSON to the capture server from the mask
// session's page.
func (e *e2e) captureJSON(ctx context.Context, name, body string) (int, string, error) {
	return e.api.fetch(ctx, e.maskSession, fetchRequest{URL: e.captureURL(name), Method: http.MethodPost,
		Headers: map[string]string{"Content-Type": "application/json", ngrokSkipHeader: "1"}, Body: &body})
}

// passwordJSON: a password in a JSON body sent by page JavaScript, with the
// stand-in written with \u escapes and a real value the proxy must escape.
// It runs on the file resolver: the http resolver finds stand-ins by prefix
// in the raw text, so it would not see an escaped one.
func (e *e2e) passwordJSON(ctx context.Context) error {
	v := e.values
	escaped := strings.ReplaceAll(v.jsonStandIn, "_", `_`)
	body := `{"username":"e2e-user","password":"` + escaped + `"}`
	status, answer, err := e.captureJSON(ctx, "password-json", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the capture server answered %d: %s", status, truncate(answer, 300))
	}
	raw, ok := e.capture.received("password-json")
	if !ok {
		return errors.New("the capture server received no request")
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		return fmt.Errorf("the capture server received a body that is not JSON (%d bytes): %w", len(raw), err)
	}
	return expect("password", got["password"], v.jsonReal, v.jsonStandIn)
}

var swapLogLine = regexp.MustCompile(`msg="swapped stand-ins in a request`)

// masking: with response masking on, the capture server receives the real
// value and answers it back, and the page sees the stand-in. The proof of
// the swap is what the capture server received, read directly by this test,
// so it does not depend on the browser seeing the real value; the proxy log
// must also show a swap for the request.
func (e *e2e) masking(ctx context.Context) error {
	v := e.values
	swapsBefore := len(swapLogLine.FindAllString(proxyLogs(e.maskProxy.name), -1))
	body := `{"secret":"` + v.maskStandIn + `"}`
	status, answer, err := e.captureJSON(ctx, "masking", body)
	if err != nil {
		return err
	}
	var errs []error
	if status != http.StatusOK {
		errs = append(errs, fmt.Errorf("the capture server answered %d: %s", status, truncate(answer, 300)))
	}
	if strings.Contains(answer, v.maskReal) {
		errs = append(errs, errors.New("the page saw the real value"))
	}
	if !strings.Contains(answer, v.maskStandIn) {
		errs = append(errs, fmt.Errorf("the page did not see the stand-in: %s", truncate(answer, 300)))
	}
	raw, ok := e.capture.received("masking")
	var got map[string]any
	switch {
	case !ok:
		errs = append(errs, errors.New("the capture server received no request"))
	case json.Unmarshal(raw, &got) != nil:
		errs = append(errs, fmt.Errorf("the capture server received a body that is not JSON (%d bytes)", len(raw)))
	default:
		errs = append(errs, expect("the upstream secret", got["secret"], v.maskReal, v.maskStandIn))
	}
	if after := len(swapLogLine.FindAllString(proxyLogs(e.maskProxy.name), -1)); after <= swapsBefore {
		errs = append(errs, errors.New("the proxy log shows no swap for the request"))
	}
	return errors.Join(errs...)
}

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

var (
	blockedRules sync.Map
	wafLogFile   *os.File
)

type RuleInfo struct {
	RuleID   int
	Message  string
	Severity string
}

type contextKey string

const requestIDKey contextKey = "requestID"

func main() {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:3000"
	}

	proxyPort := os.Getenv("PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "9090"
	}

	// Open log file for executor to read
	var err error
	wafLogFile, err = os.OpenFile("/var/log/waf/waf.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Warning: Could not open WAF log file: %v", err)
	}

	target, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Failed to parse backend URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	waf := createWAF()

	// Wrap proxy handler with WAF using Coraza's HTTP middleware
	wafHandler := txhttp.WrapHandler(waf, proxy)

	// Wrap with logging middleware
	handler := loggingMiddleware(wafHandler)

	fmt.Printf("Coraza WAF Proxy running on :%s\n", proxyPort)
	fmt.Printf("Forwarding to: %s\n", backendURL)

	log.Fatal(http.ListenAndServe(":"+proxyPort, handler))
}

func createWAF() coraza.WAF {
	// Debug logger writes to file for executor to read
	var logger debuglog.Logger
	if wafLogFile != nil {
		logger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(wafLogFile)
	} else {
		logger = debuglog.Default().WithLevel(debuglog.LevelDebug)
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDebugLogger(logger).
			WithDirectivesFromFile("./coraza.conf"),
	)
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func logError(mr types.MatchedRule) {
	uri := mr.URI()
	blockedRules.Store(uri, &RuleInfo{
		RuleID:   mr.Rule().ID(),
		Message:  mr.Message(),
		Severity: mr.Rule().Severity().String(),
	})

	// Also write to log file
	logWAF("[BLOCKED] Rule %d: %s [%s]\n", mr.Rule().ID(), mr.Message(), mr.Rule().Severity().String())
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		uri := r.URL.String()

		contentType := r.Header.Get("Content-Type")
		contentLength := r.ContentLength
		logWAF("[REQ] %s %s | Content-Type: %s | Length: %d\n",
			r.Method, uri, contentType, contentLength)

		ctx := context.WithValue(r.Context(), requestIDKey, uri)
		r = r.WithContext(ctx)

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		var ruleInfo string
		if info, ok := blockedRules.LoadAndDelete(uri); ok {
			ri := info.(*RuleInfo)
			ruleInfo = fmt.Sprintf(" | BLOCKED by rule %d: %s", ri.RuleID, ri.Message)
		}

		logWAF("[RES] %s %s | %d | %v%s\n",
			r.Method, uri, wrapped.statusCode, duration, ruleInfo)
	})
}

func logWAF(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Print(msg)
	if wafLogFile != nil {
		wafLogFile.WriteString(time.Now().Format("15:04:05") + " " + msg)
		wafLogFile.Sync()
	}
}

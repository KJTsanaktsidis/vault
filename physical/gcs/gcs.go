package gcs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/helper/useragent"
	"github.com/hashicorp/vault/physical"

	"cloud.google.com/go/storage"
	"github.com/armon/go-metrics"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// Verify Backend satisfies the correct interfaces
var _ physical.Backend = (*Backend)(nil)

const (
	// envBucket is the name of the environment variable to search for the
	// storage bucket name.
	envBucket = "GOOGLE_STORAGE_BUCKET"

	// envChunkSize is the environment variable to serach for the chunk size for
	// requests.
	envChunkSize = "GOOGLE_STORAGE_CHUNK_SIZE"

	// envHAEnabled is the name of the environment variable to search for the
	// boolean indicating if HA is enabled.
	envHAEnabled = "GOOGLE_STORAGE_HA_ENABLED"

	// defaultChunkSize is the number of bytes the writer will attempt to write in
	// a single request.
	defaultChunkSize = "8192"

	// objectDelimiter is the string to use to delimit objects.
	objectDelimiter = "/"
)

var (
	// metricDelete is the key for the metric for measuring a Delete call.
	metricDelete = []string{"gcs", "delete"}

	// metricGet is the key for the metric for measuring a Get call.
	metricGet = []string{"gcs", "get"}

	// metricList is the key for the metric for measuring a List call.
	metricList = []string{"gcs", "list"}

	// metricPut is the key for the metric for measuring a Put call.
	metricPut = []string{"gcs", "put"}
)

// Backend implements physical.Backend and describes the steps necessary to
// persist data in Google Cloud Storage.
type Backend struct {
	// bucket is the name of the bucket to use for data storage and retrieval.
	bucket string

	// chunkSize is the chunk size to use for requests.
	chunkSize int

	// client is the underlying API client for talking to gcs.
	client *storage.Client

	// haEnabled indicates if HA is enabled.
	haEnabled bool

	// logger and permitPool are internal constructs
	logger     log.Logger
	permitPool *physical.PermitPool

	keyLogger io.WriteCloser
}

// NewBackend constructs a Google Cloud Storage backend with the given
// configuration. This uses the official Golang Cloud SDK and therefore supports
// specifying credentials via envvars, credential files, etc. from environment
// variables or a service account file
func NewBackend(c map[string]string, logger log.Logger) (physical.Backend, error) {
	logger.Debug("configuring backend")

	// Bucket name
	bucket := os.Getenv(envBucket)
	if bucket == "" {
		bucket = c["bucket"]
	}
	if bucket == "" {
		return nil, errors.New("missing bucket name")
	}

	// Chunk size
	chunkSizeStr := os.Getenv(envChunkSize)
	if chunkSizeStr == "" {
		chunkSizeStr = c["chunk_size"]
	}
	if chunkSizeStr == "" {
		chunkSizeStr = defaultChunkSize
	}
	chunkSize, err := strconv.Atoi(chunkSizeStr)
	if err != nil {
		return nil, errwrap.Wrapf("failed to parse chunk_size: {{err}}", err)
	}

	// Values are specified as kb, but the API expects them as bytes.
	chunkSize = chunkSize * 1024

	// HA configuration
	haEnabled := false
	haEnabledStr := os.Getenv(envHAEnabled)
	if haEnabledStr == "" {
		haEnabledStr = c["ha_enabled"]
	}
	if haEnabledStr != "" {
		var err error
		haEnabled, err = strconv.ParseBool(haEnabledStr)
		if err != nil {
			return nil, errwrap.Wrapf("failed to parse HA enabled: {{err}}", err)
		}
	}

	// Max parallel
	maxParallel, err := extractInt(c["max_parallel"])
	if err != nil {
		return nil, errwrap.Wrapf("failed to parse max_parallel: {{err}}", err)
	}

	logger.Debug("configuration",
		"bucket", bucket,
		"chunk_size", chunkSize,
		"ha_enabled", haEnabled,
		"max_parallel", maxParallel,
	)
	logger.Debug("creating client")

	ctx := context.Background()
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: false,
	}
	tlsConfig := &tls.Config{}

	var keyLogger io.WriteCloser
	didReturnKeyLogger := false
	defer func() {
		if keyLogger != nil && !didReturnKeyLogger {
			keyLogger.Close()
		}
	}()
	if keylogFile, ok := os.LookupEnv("SSLKEYLOGFILE"); ok {
		keyLogger, err = os.OpenFile(keylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, errwrap.Wrapf("failed to open SSLKEYLOGFILE: {{err}}", err)
		}
		tlsConfig.KeyLogWriter = keyLogger
	}

	httpTransport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if err := http2.ConfigureTransport(httpTransport); err != nil {
		return nil, errwrap.Wrapf("failed to configure http2: {{err}}", err)
	}
	uaTransportWrapper := &userAgentTransport{
		base:      httpTransport,
		userAgent: useragent.String(),
	}

	tokenSource, err := google.DefaultTokenSource(ctx)

	// Client
	if credentialsFile := c["credentials_file"]; credentialsFile != "" {
		logger.Warn("specifying credentials_file as an option is " +
			"deprecated. Please use the GOOGLE_APPLICATION_CREDENTIALS environment " +
			"variable or instance credentials instead.")
		jsonKeyBytes, err := ioutil.ReadFile(credentialsFile)
		if err != nil {
			return nil, errwrap.Wrapf("failed to read credentials file: {{err}}", err)
		}
		tokenSource, err = google.JWTAccessTokenSourceFromJSON(jsonKeyBytes, storage.ScopeFullControl)
		if err != nil {
			return nil, errwrap.Wrapf("failed to construct credentials token source: {{err}}", err)
		}
	}

	oauth2Transport := &oauth2.Transport{
		Source: tokenSource,
		Base:   uaTransportWrapper,
	}
	httpClient := &http.Client{
		Transport: oauth2Transport,
	}

	client, err := storage.NewClient(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, errwrap.Wrapf("failed to create storage client: {{err}}", err)
	}

	didReturnKeyLogger = true
	return &Backend{
		bucket:    bucket,
		haEnabled: haEnabled,

		client:     client,
		permitPool: physical.NewPermitPool(maxParallel),
		logger:     logger,
		keyLogger:  keyLogger,
	}, nil
}

// Put is used to insert or update an entry
func (b *Backend) Put(ctx context.Context, entry *physical.Entry) (retErr error) {
	defer metrics.MeasureSince(metricPut, time.Now())

	// Pooling
	b.permitPool.Acquire()
	defer b.permitPool.Release()

	// Insert
	w := b.client.Bucket(b.bucket).Object(entry.Key).NewWriter(ctx)
	w.ChunkSize = b.chunkSize
	defer func() {
		closeErr := w.Close()
		if closeErr != nil {
			retErr = multierror.Append(retErr, errwrap.Wrapf("error closing connection: {{err}}", closeErr))
		}
	}()

	if _, err := w.Write(entry.Value); err != nil {
		return errwrap.Wrapf("failed to put data: {{err}}", err)
	}
	return nil
}

// Get fetches an entry. If no entry exists, this function returns nil.
func (b *Backend) Get(ctx context.Context, key string) (retEntry *physical.Entry, retErr error) {
	defer metrics.MeasureSince(metricGet, time.Now())

	// Pooling
	b.permitPool.Acquire()
	defer b.permitPool.Release()

	// Read
	r, err := b.client.Bucket(b.bucket).Object(key).NewReader(ctx)
	if err == storage.ErrObjectNotExist {
		return nil, nil
	}
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to read value for %q: {{err}}", key), err)
	}

	defer func() {
		closeErr := r.Close()
		if closeErr != nil {
			retErr = multierror.Append(retErr, errwrap.Wrapf("error closing connection: {{err}}", closeErr))
		}
	}()

	value, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errwrap.Wrapf("failed to read value into a string: {{err}}", err)
	}

	return &physical.Entry{
		Key:   key,
		Value: value,
	}, nil
}

// Delete deletes an entry with the given key
func (b *Backend) Delete(ctx context.Context, key string) error {
	defer metrics.MeasureSince(metricDelete, time.Now())

	// Pooling
	b.permitPool.Acquire()
	defer b.permitPool.Release()

	// Delete
	err := b.client.Bucket(b.bucket).Object(key).Delete(ctx)
	if err != nil && err != storage.ErrObjectNotExist {
		return errwrap.Wrapf(fmt.Sprintf("failed to delete key %q: {{err}}", key), err)
	}
	return nil
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	defer metrics.MeasureSince(metricList, time.Now())

	// Pooling
	b.permitPool.Acquire()
	defer b.permitPool.Release()

	iter := b.client.Bucket(b.bucket).Objects(ctx, &storage.Query{
		Prefix:    prefix,
		Delimiter: objectDelimiter,
		Versions:  false,
	})

	keys := []string{}

	for {
		objAttrs, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, errwrap.Wrapf("failed to read object: {{err}}", err)
		}

		var path string
		if objAttrs.Prefix != "" {
			// "subdirectory"
			path = objAttrs.Prefix
		} else {
			// file
			path = objAttrs.Name
		}

		// get relative file/dir just like "basename"
		key := strings.TrimPrefix(path, prefix)
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys, nil
}

// extractInt is a helper function that takes a string and converts that string
// to an int, but accounts for the empty string.
func extractInt(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

type userAgentTransport struct {
	userAgent string
	base      http.RoundTripper
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.base
	if rt == nil {
		return nil, errors.New("transport: no Transport specified")
	}
	if t.userAgent == "" {
		return rt.RoundTrip(req)
	}
	newReq := *req
	newReq.Header = make(http.Header)
	for k, vv := range req.Header {
		newReq.Header[k] = vv
	}
	// TODO(cbro): append to existing User-Agent header?
	newReq.Header["User-Agent"] = []string{t.userAgent}
	return rt.RoundTrip(&newReq)
}

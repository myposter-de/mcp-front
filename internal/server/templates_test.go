package server

import (
	"bytes"
	"html"
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServicesPageStateRoundTrips(t *testing.T) {
	state := "eyJhIjoiYiJ9-_=.sig="

	var buf bytes.Buffer
	require.NoError(t, servicesPageTemplate.Execute(&buf, ServicesPageData{State: state}))

	m := regexp.MustCompile(`href="(/oauth/complete\?[^"]+)"`).FindStringSubmatch(buf.String())
	require.NotNil(t, m)
	u, err := url.Parse(html.UnescapeString(m[1]))
	require.NoError(t, err)
	assert.Equal(t, state, u.Query().Get("state"))
}

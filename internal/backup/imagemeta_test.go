package backup

import "testing"

func TestParseSemverTag(t *testing.T) {
	cases := []struct {
		tag string
		ok  bool
	}{
		{"v2.7.5", true},
		{"2.7.5", true},
		{"release", false},
		{"latest", false},
		{"v3.0.1-rc1", false},
		{"v3.0", false},
	}
	for _, c := range cases {
		_, ok := parseSemverTag(c.tag)
		if ok != c.ok {
			t.Errorf("parseSemverTag(%q) ok=%v, want %v", c.tag, ok, c.ok)
		}
	}
}

func TestSemverLess(t *testing.T) {
	a, _ := parseSemverTag("v2.7.5")
	b, _ := parseSemverTag("v3.0.1")
	if !a.less(b) {
		t.Errorf("expected v2.7.5 < v3.0.1")
	}
	if b.less(a) {
		t.Errorf("expected v3.0.1 not < v2.7.5")
	}
	c, _ := parseSemverTag("v2.10.0")
	d, _ := parseSemverTag("v2.9.9")
	if !d.less(c) {
		t.Errorf("expected v2.9.9 < v2.10.0 (numeric, not lexicographic)")
	}
}

func TestLatestSemverTagPicksHighest(t *testing.T) {
	tags := []string{"release", "latest", "v2.7.5", "v3.0.1", "v2.9.9", "v3.0.1-rc1"}
	var best semver
	found := false
	for _, tg := range tags {
		sv, ok := parseSemverTag(tg)
		if !ok {
			continue
		}
		if !found || best.less(sv) {
			best = sv
			found = true
		}
	}
	if !found || best.raw != "v3.0.1" {
		t.Errorf("got %+v found=%v, want v3.0.1", best, found)
	}
}

func TestNextPageURL(t *testing.T) {
	cases := []struct {
		link string
		want string
	}{
		{`</v2/immich-app/immich-server/tags/list?n=100&last=v2.0.0>; rel="next"`,
			"https://ghcr.io/v2/immich-app/immich-server/tags/list?n=100&last=v2.0.0"},
		{`</v2/foo/tags/list?n=100>; rel="prev"`, ""},
		{``, ""},
	}
	for _, c := range cases {
		got := nextPageURL("ghcr.io", c.link)
		if got != c.want {
			t.Errorf("nextPageURL(%q) = %q, want %q", c.link, got, c.want)
		}
	}
}

func TestHostPlatformMapsCommonArches(t *testing.T) {
	// Just exercise the function; can't control docker CLI presence in test env,
	// but it must not panic and must return something for GOARCH's own value
	// via the fallback path when docker info is unavailable.
	arch, _ := hostPlatform()
	if arch == "" {
		t.Errorf("expected non-empty arch")
	}
}

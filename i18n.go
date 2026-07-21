package main

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// Localization for the scenario console. Two locales ship embedded:
// Turkish (tr, DEFAULT) and English (en, per-key fallback). Turkish is
// the default because the operators running these drills are
// Turkish-speaking.
//
// What gets localized:
//   - the console UI strings (ui.*)
//   - per-scenario name + a plain-language Purpose / Impact / Threat
//     overlay (scenario.<id>.{name,purpose,impact,threat})
//
// The English Desc / Expected / KomutaUI on the scenario struct are the
// *technical test contract* that the side-by-side test loop walks — they
// are intentionally NOT localized and left untouched. The localized
// overlay is the "why does this matter, in plain language" layer the
// operator asked for; it requires no kernel/LSM/eBPF knowledge to read.
//
// Locale resolution per request: ?lang=tr|en → Accept-Language → tr.

//go:embed i18n/tr.json i18n/en.json
var i18nFS embed.FS

// DefaultLocale — Turkish. Single source of truth for the app default.
const DefaultLocale = "tr"

type scenarioI18n struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	Impact  string `json:"impact"`
	Threat  string `json:"threat"`
}

type i18nBundle struct {
	UI       map[string]string       `json:"ui"`
	Scenario map[string]scenarioI18n `json:"scenario"`
}

// i18nBundles holds every loaded locale; read-only after loadI18n().
var i18nBundles = map[string]i18nBundle{}

func loadI18n() {
	for _, loc := range []string{"tr", "en"} {
		raw, err := i18nFS.ReadFile("i18n/" + loc + ".json")
		if err != nil {
			log.Fatalf("[komuta-test-app] i18n: read %s: %v", loc, err)
		}
		var b i18nBundle
		if err := json.Unmarshal(raw, &b); err != nil {
			log.Fatalf("[komuta-test-app] i18n: parse %s: %v", loc, err)
		}
		i18nBundles[loc] = b
	}
	if _, ok := i18nBundles[DefaultLocale]; !ok {
		log.Fatalf("[komuta-test-app] i18n: default locale %q not loaded", DefaultLocale)
	}
}

// resolveLocale picks the locale for a request. Always returns a locale
// present in i18nBundles.
func resolveLocale(r *http.Request) string {
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang"))); q != "" {
		if _, ok := i18nBundles[q]; ok {
			return q
		}
	}
	al := strings.ToLower(r.Header.Get("Accept-Language"))
	if al != "" {
		first := strings.TrimSpace(strings.SplitN(al, ",", 2)[0])
		switch {
		case strings.HasPrefix(first, "tr"):
			return "tr"
		case strings.HasPrefix(first, "en"):
			return "en"
		}
	}
	return DefaultLocale
}

// uiStrings returns the UI map for a locale with English values merged
// in as per-key fallback so a missing translation never blanks the UI.
func uiStrings(loc string) map[string]string {
	merged := make(map[string]string, len(i18nBundles["en"].UI))
	for k, v := range i18nBundles["en"].UI {
		merged[k] = v
	}
	if b, ok := i18nBundles[loc]; ok {
		for k, v := range b.UI {
			if v != "" {
				merged[k] = v
			}
		}
	}
	return merged
}

// scenarioText returns the localized name/purpose/impact/threat for a
// scenario id, falling back per-field to English then to the empty
// string (the UI hides empty fields).
func scenarioText(loc, id string) scenarioI18n {
	en := i18nBundles["en"].Scenario[id]
	cur := i18nBundles[loc].Scenario[id]
	pick := func(a, b string) string {
		if strings.TrimSpace(a) != "" {
			return a
		}
		return b
	}
	return scenarioI18n{
		Name:    pick(cur.Name, en.Name),
		Purpose: pick(cur.Purpose, en.Purpose),
		Impact:  pick(cur.Impact, en.Impact),
		Threat:  pick(cur.Threat, en.Threat),
	}
}

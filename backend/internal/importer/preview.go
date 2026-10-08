package importer

import (
	"strings"

	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/model"
	"github.com/Krifmaz/CaddyHub/internal/registry"
)

// PreviewInput builds generator input as if the import had been committed,
// so the result can be regenerated and compared before anything is saved.
// Secret values are replaced by a dummy placeholder; only structure matters.
func PreviewInput(res *Result, settings model.Settings, env generator.Env, caps registry.Capabilities) generator.Input {
	in := generator.Input{Settings: settings, Env: env, Caps: caps, Credentials: map[int64]generator.CredRef{}}
	if res.Email != "" {
		in.Settings.ACMEEmail = res.Email
	}
	if res.ACMECA != "" {
		in.Settings.ACMECA, in.Settings.ACMECAURL = res.ACMECA, res.ACMECAURL
	}
	if res.RawGlobal != "" {
		in.Settings.RawGlobal = res.RawGlobal
	}
	credID := map[string]int64{}
	for i, c := range res.Credentials {
		id := int64(i + 1)
		credID[c.Key] = id
		ref := generator.CredRef{Provider: c.Provider, Fields: map[string]string{}}
		for k, v := range c.Fields {
			switch {
			case strings.HasPrefix(v, "env:"):
				ref.Fields[k] = "{env." + strings.TrimPrefix(v, "env:") + "}"
			case strings.HasPrefix(v, "file:"):
				ref.Fields[k] = "{file." + strings.TrimPrefix(v, "file:") + "}"
			default:
				ref.Fields[k] = "{env.CADDYHUB_IMPORT_PREVIEW}"
			}
		}
		in.Credentials[id] = ref
	}
	for i, d := range res.Domains {
		dom := model.Domain{ID: int64(i + 1), Name: d.Name, Challenge: d.Challenge, Wildcard: d.Wildcard}
		if id, ok := credID[d.CredentialKey]; ok {
			dom.CredentialID = &id
		} else if dom.Challenge == model.ChallengeDNS {
			dom.Challenge, dom.Wildcard = model.ChallengeHTTP, false
		}
		in.Domains = append(in.Domains, dom)
	}
	for i, s := range res.Sites {
		s.ID, s.Position = int64(i+1), i+1
		in.Sites = append(in.Sites, s)
	}
	in.Snippets = res.Snippets
	in.RawBlocks = res.RawBlocks
	return in
}

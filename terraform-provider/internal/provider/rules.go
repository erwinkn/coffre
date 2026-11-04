package provider

import (
	"fmt"
	"regexp"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

// The rules of docs/design/terraform-provider.md, section 5, kept apart
// from Terraform's types so that their tables test as tables.

// keyName is coffre's own check of a key's name.
var keyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// rank orders the natures: a higher one is stricter.
var rank = map[string]int{"plain": 0, "secret": 1, "sensitive": 2}

// looser reports whether making a key `to` from `from` loosens it.
func looser(from, to string) bool { return rank[to] < rank[from] }

// kept is what the resource keeps in private state, besides its state:
// the version Terraform last wrote, by the write's own receipt, and the
// key's place in a fork as the last list showed it.
type kept struct {
	Written string `json:"written,omitempty"`
	Parent  string `json:"parent,omitempty"`
}

// changeKind is what an update does.
type changeKind int

const (
	nothing changeKind = iota // keep version and version_id; call nothing
	write                     // send value_wo as a new version
	mark                      // make the current value stricter, a new version holding it
)

// planned is what a plan holds for an update, before its apply.
type planned struct {
	Kind  changeKind
	Error string // the plan's error, when the change may not be made
}

// planUpdate decides an update at plan: section 5's table. stateVersion
// is the prior state's value_wo_version (nil once imported), planVersion
// the configuration's (nil while unknown).
func planUpdate(id string, stateVersion, planVersion *string, stateNature, planNature string, natureKnown bool, parent string) planned {
	if stateVersion == nil || planVersion == nil || *stateVersion != *planVersion {
		return planned{Kind: write}
	}
	if !natureKnown {
		return planned{Kind: mark}
	}
	if stateNature == planNature {
		return planned{Kind: nothing}
	}
	if looser(stateNature, planNature) {
		return planned{Error: fmt.Sprintf("making %s %s writes its value again; change value_wo_version in the same apply", id, planNature)}
	}
	if parent == "inherited" {
		return planned{Error: fmt.Sprintf("%s has no value of its own to mark; change value_wo_version to write one", id)}
	}
	return planned{Kind: mark}
}

// applyUpdate decides an update at apply, the configuration now known: a
// value_wo_version unknown at plan writes only if it differs from the
// state's.
func applyUpdate(id string, stateVersion *string, planVersion string, stateNature, planNature, parent string) planned {
	if stateVersion == nil || *stateVersion != planVersion {
		return planned{Kind: write}
	}
	return planUpdate(id, stateVersion, &planVersion, stateNature, planNature, true, parent)
}

// refreshed is what a refresh makes of a key as coffre lists it.
type refreshed struct {
	Remove      bool    // the key is gone: the resource leaves state
	Error       string  // the refresh fails, saying why
	Warning     string  // the refresh goes on, and says this
	Version     *int64  // the state's version, null where the list says none
	VersionID   *string // likewise its id
	Sensitivity *string // the state's sensitivity, or nil to keep it
	Parent      string  // the key's place in a fork, for private state
}

// refresh reads a key's listing: section 5's table "Values written
// outside Terraform".
func refresh(id string, key *coffre.Key, private kept) refreshed {
	if key == nil {
		return refreshed{Remove: true}
	}
	if key.Archived {
		return refreshed{Error: fmt.Sprintf("%s is archived in coffre: unarchive it there (coffre unarchive %s), or remove the resource", id, id)}
	}
	if key.IsReference() {
		return refreshed{Error: fmt.Sprintf("%s is a reference in coffre, to another key's value: a reference is not Terraform's to overwrite; remove the resource, or end the reference in coffre", id)}
	}
	parent := ""
	if key.Parent != nil {
		parent = key.Parent.State
	}
	switch parent {
	case "removed":
		return refreshed{Error: fmt.Sprintf("%s is removed in this fork: restore it there, or remove the resource", id)}
	case "inherited":
		// An override reset to the parent's: reported, never overwritten unasked; the state keeps Terraform's nature.
		return refreshed{
			Version: key.Version, VersionID: key.VersionID, Parent: parent,
			Warning: fmt.Sprintf("%s has no value of its own now: the fork reads its parent's (%s). Terraform does not write it back unasked: change value_wo_version to write Terraform's value as an override again", id, key.Parent.From),
		}
	}
	out := refreshed{Version: key.Version, VersionID: key.VersionID, Sensitivity: key.Sensitivity, Parent: parent}
	if private.Written != "" && (key.VersionID == nil || *key.VersionID != private.Written) {
		by := "someone"
		if key.UpdatedBy != nil && *key.UpdatedBy != "" {
			by = *key.UpdatedBy
		}
		version := "a version"
		if key.Version != nil {
			version = fmt.Sprintf("version %d", *key.Version)
		}
		out.Warning = fmt.Sprintf("%s holds %s, written by %s outside Terraform. Terraform does not overwrite it: change value_wo_version to write Terraform's value again", id, version, by)
	}
	return out
}

// creatable says whether a create may write a key as coffre lists it, and
// over which version: none, or in a fork the inherited one, when the list
// shows it.
func creatable(id string, key *coffre.Key) (replaces *string, problem string) {
	if key == nil {
		return nil, ""
	}
	if key.Parent != nil && key.Parent.State == "removed" {
		return nil, fmt.Sprintf("%s is removed in this fork: restore it there first", id)
	}
	if key.Archived {
		return nil, fmt.Sprintf("%s is archived in coffre: unarchive it there and import it, or archive nothing and pick another key", id)
	}
	if key.IsReference() {
		return nil, fmt.Sprintf("%s is a reference in coffre: a reference is not Terraform's to overwrite", id)
	}
	if key.Parent != nil && key.Parent.State == "inherited" {
		// An override over the parent's value: guarded by the inherited version, when the list shows it.
		return key.VersionID, ""
	}
	return nil, fmt.Sprintf("%s exists in coffre; import it (terraform import <address> %s) to manage it", id, id)
}

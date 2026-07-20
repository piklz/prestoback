package backup

// restorepreview.go — pre-restore dry-run: walks an archive and compares
// every entry against what's already on disk at the intended destination,
// WITHOUT extracting or writing anything, so the result is a preview of
// what a real restore would do rather than a side effect of doing it.
//
// Why this is worth having even though RestoreVolume already takes an
// automatic pre-restore safety snapshot (engine.go): that snapshot is
// undo protection AFTER the fact — it doesn't tell you anything before
// you commit. This is a genuinely different property: surfacing surprises
// BEFORE you click restore, which matters most in exactly the situations
// this codebase already went out of its way to handle correctly —
// restoring onto a different host where the PUID/PGID convention doesn't
// match (see engine.go's ownership-preservation work), or an archive with
// a symlink whose target won't exist after restore. A snapshot can undo a
// bad restore; a preview can help you not need to.
//
// Deliberately stat-based, not a full extraction to a scratch directory
// and diff. A busy Plex library backup can run to tens of thousands of
// entries (see the symlink-scale testing this codebase's restore path
// already went through) — fully extracting a preview copy just to diff it
// would double the disk I/O and require as much free space as the restore
// itself, defeating half the point of a "cheap look before you leap"
// feature. Comparing size+mtime+mode+uid/gid against a live os.Lstat is
// the same "quick check" heuristic rsync and GNU tar's own --compare use:
// it can't catch a file that changed content but kept an identical size
// and mtime (a deliberately adversarial or clock-skewed edge case), but
// it catches everything a real restore scenario actually produces, at a
// tiny fraction of the I/O cost.

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PreviewChange describes what a real restore would do to one path.
type PreviewChange string

const (
	ChangeAdd          PreviewChange = "add"          // path doesn't exist yet
	ChangeModify       PreviewChange = "modify"        // exists, content/size/mtime differs
	ChangeTypeConflict PreviewChange = "type_conflict" // exists as a DIFFERENT kind of thing (e.g. archive has a dir, disk has a file) — a real restore would likely fail partway through on this exact entry
	ChangeUnchanged    PreviewChange = "unchanged"      // exists, nothing about it looks different
)

// PreviewEntry is one archive entry whose restore would have a visible
// effect — unchanged entries are counted (see RestorePreview.Unchanged)
// but not listed individually, since for a large library that list would
// dwarf the entries anyone actually needs to look at.
type PreviewEntry struct {
	Path               string        `json:"path"`
	Change             PreviewChange `json:"change"`
	OwnershipChanges   bool          `json:"ownership_changes,omitempty"` // uid/gid would change, independent of Change
	PermissionChanges  bool          `json:"permission_changes,omitempty"`
	OldOwner           string        `json:"old_owner,omitempty"` // "uid:gid" of what's currently on disk — "" if the path doesn't exist yet
	NewOwner           string        `json:"new_owner,omitempty"` // "uid:gid" the archive would apply
	OldSizeBytes       int64         `json:"old_size_bytes,omitempty"`
	NewSizeBytes       int64         `json:"new_size_bytes,omitempty"`
}

// RestorePreview summarizes what a real restore of this archive to
// destPath would do. Counts always reflect EVERY entry in the archive;
// Entries is capped (see previewMaxListedEntries) so the response stays a
// reasonable size for a library with tens of thousands of files — Truncated
// tells the caller there was more than what's listed.
type RestorePreview struct {
	TotalEntries      int            `json:"total_entries"`
	Unchanged         int            `json:"unchanged"`
	WillAdd           int            `json:"will_add"`
	WillModify        int            `json:"will_modify"`
	TypeConflicts     int            `json:"type_conflicts"`
	OwnershipChanges  int            `json:"ownership_changes"`
	PermissionChanges int            `json:"permission_changes"`
	Entries           []PreviewEntry `json:"entries"`
	Truncated         bool           `json:"truncated"`
	// NeverDeletes is always true today, included explicitly in the
	// response (not just a code comment) so the UI can state it plainly —
	// restore is additive/overwrite-only (see RestoreVolume in engine.go);
	// a file present on disk but absent from the archive is never removed,
	// which is easy for a user to wrongly assume otherwise given how
	// "restore" behaves in most other backup tools.
	NeverDeletes bool `json:"never_deletes"`
}

// previewMaxListedEntries caps PreviewEntry list length. Counts in the
// summary fields are always exact regardless of this cap — only the
// itemized list is bounded.
const previewMaxListedEntries = 500

// PreviewRestore walks archivePath (already decrypted, if it was
// encrypted — same split RestoreVolume/extractTarGz already use, where
// decryption is the caller's job and this function only ever sees a plain
// tar.gz) and compares it against destPath, without writing anything.
func PreviewRestore(archivePath, destPath string) (*RestorePreview, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	preview := &RestorePreview{NeverDeletes: true}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		parts := strings.SplitN(filepath.ToSlash(hdr.Name), "/", 2)
		var rel string
		if len(parts) > 1 {
			rel = parts[1]
		} else {
			rel = hdr.Name
		}
		if rel == "" || rel == "/" {
			continue
		}
		target := filepath.Join(destPath, filepath.Clean("/"+rel))
		if !strings.HasPrefix(target, filepath.Clean(destPath)+string(os.PathSeparator)) {
			continue // same suspicious-path guard extractTarGz applies; silently skip in a preview rather than warn twice
		}

		preview.TotalEntries++
		entry := classifyEntry(target, hdr)

		switch entry.Change {
		case ChangeAdd:
			preview.WillAdd++
		case ChangeModify:
			preview.WillModify++
		case ChangeTypeConflict:
			preview.TypeConflicts++
		case ChangeUnchanged:
			preview.Unchanged++
		}
		if entry.OwnershipChanges {
			preview.OwnershipChanges++
		}
		if entry.PermissionChanges {
			preview.PermissionChanges++
		}

		// Only entries with a visible effect are worth listing — an
		// unchanged file with unchanged ownership is exactly the case
		// this preview exists to let the user skip past.
		if entry.Change != ChangeUnchanged || entry.OwnershipChanges || entry.PermissionChanges {
			if len(preview.Entries) < previewMaxListedEntries {
				preview.Entries = append(preview.Entries, entry)
			} else {
				preview.Truncated = true
			}
		}
	}
	return preview, nil
}

// lstatOwner extracts uid/gid from an os.FileInfo's platform-specific Sys()
// value. Safe (comma-ok) type assertion rather than a blind one — this
// codebase targets Linux only (see the Dockerfile and docker-build.yml's
// linux/amd64+linux/arm64 platforms), where this always succeeds, but a
// safe assertion costs nothing and avoids a panic if that ever changes.
func lstatOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func ownerString(uid, gid int) string {
	return fmt.Sprintf("%d:%d", uid, gid)
}
// currently on disk at target (if anything), via Lstat — never resolves
// symlinks, matching extractTarGz's own Lchown-not-Chown posture: a
// symlink's own metadata is what's being compared, not its target's.
// classifyEntry compares one archive entry's header against whatever's
// currently on disk at target (if anything), via Lstat — never resolves
// symlinks, matching extractTarGz's own Lchown-not-Chown posture: a
// symlink's own metadata is what's being compared, not its target's.
func classifyEntry(target string, hdr *tar.Header) PreviewEntry {
	e := PreviewEntry{
		Path:         hdr.Name,
		NewOwner:     ownerString(hdr.Uid, hdr.Gid),
		NewSizeBytes: hdr.Size,
	}

	fi, err := os.Lstat(target)
	if err != nil {
		e.Change = ChangeAdd
		return e
	}

	liveUID, liveGID, hasOwner := lstatOwner(fi)
	if hasOwner {
		e.OldOwner = ownerString(liveUID, liveGID)
		if liveUID != hdr.Uid || liveGID != hdr.Gid {
			e.OwnershipChanges = true
		}
	}
	e.OldSizeBytes = fi.Size()
	if fi.Mode().Perm() != os.FileMode(hdr.Mode).Perm() {
		e.PermissionChanges = true
	}

	archiveIsDir := hdr.Typeflag == tar.TypeDir
	archiveIsSymlink := hdr.Typeflag == tar.TypeSymlink
	archiveIsReg := hdr.Typeflag == tar.TypeReg

	liveIsDir := fi.IsDir()
	liveIsSymlink := fi.Mode()&os.ModeSymlink != 0
	liveIsReg := fi.Mode().IsRegular()

	switch {
	case archiveIsDir && !liveIsDir:
		e.Change = ChangeTypeConflict
	case archiveIsSymlink && !liveIsSymlink:
		e.Change = ChangeTypeConflict
	case archiveIsReg && !liveIsReg:
		e.Change = ChangeTypeConflict
	case archiveIsDir:
		// Directories have no content to diff — presence + type match is
		// "unchanged" regardless of mtime (a dir's mtime changes just from
		// its children changing, which would be noisy and misleading here).
		e.Change = ChangeUnchanged
	case archiveIsSymlink:
		liveTarget, readErr := os.Readlink(target)
		if readErr != nil || liveTarget != hdr.Linkname {
			e.Change = ChangeModify
		} else {
			e.Change = ChangeUnchanged
		}
	default: // regular file
		// mtimeToleranceSeconds, not exact equality: different filesystems
		// disagree on mtime granularity (FAT32 rounds to 2s; some network
		// and overlay filesystems round inconsistently), and the backup
		// source and restore destination are never guaranteed to be the
		// same filesystem type. Exact-second equality produced false
		// "modified" flags purely from storage rounding during testing,
		// not from any real content difference — a couple of seconds of
		// slack costs essentially nothing in false negatives (a file that
		// genuinely changed almost never does so within 2s of its old
		// mtime by coincidence) and removes a whole class of
		// filesystem-dependent false positives.
		const mtimeToleranceSeconds = 2
		diff := hdr.ModTime.Unix() - fi.ModTime().Unix()
		if diff < 0 {
			diff = -diff
		}
		if fi.Size() != hdr.Size || diff > mtimeToleranceSeconds {
			e.Change = ChangeModify
		} else {
			e.Change = ChangeUnchanged
		}
	}
	return e
}

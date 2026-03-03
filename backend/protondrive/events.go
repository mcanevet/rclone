package protondrive

// events.go contains the background event poller, cache-flush logic, and the
// ChangeNotify implementation for the Proton Drive backend.

import (
	"context"
	"errors"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
)

// flushCaches resets the directory cache and the link keyring cache.
// It must be called whenever remote state may have changed (e.g. on events
// or after a DirCacheFlush).
func (f *Fs) flushCaches() {
	f.dirCache.ResetRoot()
	f.linkKRCache.Purge()
}

// resolveLinkPath attempts to derive the rclone-relative path for a link event.
// lw is the full link metadata (fetched via batchGetLinks); parentLinkID is
// the parent from the event's Link.ParentLinkID field.
// It uses the dircache reverse lookup for the parent and decrypts the link
// name using the cached parent keyring.  If either step fails, it returns "".
func (f *Fs) resolveLinkPath(lw protondriveapi.LinkWrapper, parentLinkID string) string {
	if parentLinkID == "" {
		return ""
	}

	// Look up the parent's path in the dircache (reverse lookup: id → path).
	parentPath, ok := f.dirCache.GetInv(parentLinkID)
	if !ok {
		fs.Debugf(f, "resolveLinkPath: parentLinkID %s not in dircache", parentLinkID)
		return ""
	}

	// Fetch the cached parent keyring — needed to decrypt the link name.
	parentKR, ok := f.linkKRCache.Get(parentLinkID)
	if !ok || parentKR == nil {
		fs.Debugf(f, "resolveLinkPath: parentLinkID %s not in linkKRCache", parentLinkID)
		return ""
	}

	// Decrypt the encrypted name.
	nameMsg, err := pgpcrypto.NewPGPMessageFromArmored(lw.Link.Name)
	if err != nil {
		fs.Debugf(f, "resolveLinkPath: parse name: %v", err)
		return ""
	}
	plainName, err := parentKR.Decrypt(nameMsg, nil, pgpcrypto.GetUnixTime())
	if err != nil {
		fs.Debugf(f, "resolveLinkPath: decrypt name: %v", err)
		return ""
	}
	name := f.opt.Enc.ToStandardName(string(plainName.GetBinary()))

	if parentPath == "" {
		return name
	}
	return parentPath + "/" + name
}

// notifyEvents calls the registered notifyFunc for a batch of drive events,
// or flushes caches if no notifyFunc is registered.
// When a notifyFunc is registered it batch-fetches full link metadata (while
// the dircache is still warm), resolves paths, delivers notifications, and
// only then flushes caches — so the dircache stays alive across event batches.
// When no notifyFunc is registered the caches are flushed immediately so that
// subsequent rclone operations see up-to-date metadata.
func (f *Fs) notifyEvents(ctx context.Context, events []protondriveapi.DriveEventLink) {
	if len(events) == 0 {
		return
	}

	f.notifyMu.Lock()
	fn := f.notifyFunc
	f.notifyMu.Unlock()

	if fn == nil {
		// Passive mode: just flush so callers get fresh data on next access.
		fs.Debugf(f, "event poller: %d events, flushing caches (no notify fn)", len(events))
		f.flushCaches()
		return
	}

	fs.Debugf(f, "event poller: %d events, resolving paths", len(events))

	// Collect link IDs for non-delete events (deletes have no metadata to fetch).
	var linkIDs []string
	for _, ev := range events {
		if ev.EventType != protondriveapi.EventActionDelete && ev.Link.LinkID != "" {
			linkIDs = append(linkIDs, ev.Link.LinkID)
		}
	}

	// Batch-fetch full link metadata (name, type) for all relevant links.
	linkByID := map[string]protondriveapi.LinkWrapper{}
	if len(linkIDs) > 0 {
		var wrappers []protondriveapi.LinkWrapper
		if err := f.pacer.Call(func() (bool, error) {
			var e error
			wrappers, e = f.client.BatchGetLinks(ctx, f.volumeID, linkIDs)
			return shouldRetry(ctx, e)
		}); err != nil && !errors.Is(err, protondriveapi.ErrPartialLinks) {
			fs.Debugf(f, "notifyEvents: batchGetLinks: %v", err)
		} else {
			if err != nil {
				fs.Debugf(f, "notifyEvents: batchGetLinks partial: %v", err)
			}
			for _, lw := range wrappers {
				linkByID[lw.Link.LinkID] = lw
			}
		}
	}

	// Resolve paths while the dircache and linkKRCache are still populated.
	type notification struct {
		path      string
		entryType fs.EntryType
	}
	notified := map[string]bool{}
	var notes []notification
	hasUnresolved := false
	for _, ev := range events {
		if ev.Link.LinkID == "" {
			continue
		}
		lw, ok := linkByID[ev.Link.LinkID]
		if !ok {
			// Delete events or links we couldn't fetch — can't resolve path.
			// Mark as unresolved so we flush caches after delivering notifications.
			hasUnresolved = true
			continue
		}
		p := f.resolveLinkPath(lw, ev.Link.ParentLinkID)
		if p == "" {
			hasUnresolved = true
			continue
		}
		if notified[p] {
			continue
		}
		notified[p] = true
		entryType := fs.EntryDirectory
		if lw.Link.Type == protondriveapi.LinkTypeFile {
			entryType = fs.EntryObject
		}
		notes = append(notes, notification{path: p, entryType: entryType})
	}

	// Deliver notifications — the callback will trigger re-listing which
	// repopulates the dircache.  For delete events and other unresolved links
	// (whose paths cannot be determined) we flush the caches directly so that
	// stale entries are not served on subsequent accesses.
	for _, n := range notes {
		fn(n.path, n.entryType)
	}
	if hasUnresolved {
		fs.Debugf(f, "notifyEvents: flushing caches for unresolved/delete events")
		f.flushCaches()
	}
}

// startEventPoller starts a background goroutine that polls for drive events
// and invalidates the dir cache and link KR cache when changes are detected.
// If a notifyFunc has been registered (via ChangeNotify), it is called for
// each changed link with the resolved path and entry type.
// The poll interval can be dynamically updated via f.pollIntervalC.
func (f *Fs) startEventPoller(ctx context.Context) {
	// Use f.ctx (derived via context.WithoutCancel) so the poller is not
	// cancelled when the caller's short-lived request context expires (e.g.
	// during rclone mount).  f.ctx still propagates rclone config values.
	pollerCtx, cancel := context.WithCancel(f.ctx)
	f.stopPoller = cancel
	go func() {
		defer cancel()
		// Get the latest event ID to use as our starting point.
		// PACE: GetLatestEventID via pacer
		var lastEventID string
		if err := f.pacer.Call(func() (bool, error) {
			var e error
			lastEventID, e = f.client.GetLatestEventID(pollerCtx, f.volumeID)
			return shouldRetry(pollerCtx, e)
		}); err != nil {
			fs.Debugf(f, "event poller: failed to get latest event ID: %v", err)
			lastEventID = ""
		}

		interval := eventPollInterval
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-pollerCtx.Done():
				return
			case newInterval := <-f.pollIntervalC:
				if newInterval == 0 {
					// Interval 0 means stop polling; park the ticker at a very
					// long interval so the goroutine stays alive but idle.
					ticker.Stop()
				} else if newInterval != interval {
					interval = newInterval
					ticker.Reset(interval)
				}
			case <-ticker.C:
				if lastEventID == "" {
					// PACE: GetLatestEventID via pacer
					var pollID string
					if err := f.pacer.Call(func() (bool, error) {
						var e error
						pollID, e = f.client.GetLatestEventID(pollerCtx, f.volumeID)
						return shouldRetry(pollerCtx, e)
					}); err != nil {
						fs.Debugf(f, "event poller: get latest event ID: %v", err)
						continue
					}
					lastEventID = pollID
					continue
				}

				// PACE: PollEvents via pacer
				var events *protondriveapi.DriveEventResp
				if err := f.pacer.Call(func() (bool, error) {
					var e error
					events, e = f.client.PollEvents(pollerCtx, f.volumeID, lastEventID)
					return shouldRetry(pollerCtx, e)
				}); err != nil {
					fs.Debugf(f, "event poller: poll events: %v", err)
					continue
				}

				f.notifyEvents(pollerCtx, events.Events)

				if events.EventID != "" {
					lastEventID = events.EventID
				}

				// If there are more events, advance with a small pause between
				// requests to avoid hammering the API in pathological cases.
				for events.More && events.EventID != "" {
					// PACE: Use the pacer for every follow-up PollEvents API call as well.
					var followupEvents *protondriveapi.DriveEventResp
					pollErr := f.pacer.Call(func() (bool, error) {
						var e error
						followupEvents, e = f.client.PollEvents(pollerCtx, f.volumeID, events.EventID)
						return shouldRetry(pollerCtx, e)
					})
					if pollErr != nil {
						fs.Debugf(f, "event poller: follow-up poll: %v", pollErr)
						break
					}
					f.notifyEvents(pollerCtx, followupEvents.Events)
					if followupEvents.EventID != "" {
						lastEventID = followupEvents.EventID
					}
					events = followupEvents
				}
			}
		}
	}()
}

// ChangeNotify calls fn with a path and entry type whenever drive events are
// observed.  It respects the poll interval supplied via pollIntervalChan.
// Implements fs.ChangeNotifier.
func (f *Fs) ChangeNotify(ctx context.Context, fn func(string, fs.EntryType), pollIntervalChan <-chan time.Duration) {
	// Register the notify function so the background poller calls it.
	f.notifyMu.Lock()
	f.notifyFunc = fn
	f.notifyMu.Unlock()

	deregister := func() {
		f.notifyMu.Lock()
		f.notifyFunc = nil
		f.notifyMu.Unlock()
	}

	// Forward poll interval changes to the background poller.  Exit when
	// the channel is closed or the caller's context is cancelled, and
	// deregister the notify function in either case.
	go func() {
		for {
			select {
			case <-ctx.Done():
				deregister()
				return
			case interval, ok := <-pollIntervalChan:
				if !ok {
					// Channel closed: deregister.
					deregister()
					return
				}
				// Update the poller's interval (non-blocking in case poller is busy).
				select {
				case f.pollIntervalC <- interval:
				default:
					// Overwrite stale pending interval.
					select {
					case <-f.pollIntervalC:
					default:
					}
					f.pollIntervalC <- interval
				}
			}
		}
	}()
}

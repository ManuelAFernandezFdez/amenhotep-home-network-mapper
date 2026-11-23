# Amenhotep — Quickstart: the presence watcher (`amenhotep watch`)

A normal scan is a snapshot: devices that are asleep or switched off at that moment stay hidden. The **watch** pass runs often and cheaply, so devices are caught when they wake up, and you can see who is online now and when each device is usually online.

## What one pass does (about 25 seconds)

1. Quick ping/ARP sweep of your local network.
2. Reads the kernel neighbour table.
3. Listens for mDNS and asks each live host for its name.
4. Records every device it saw (that is the "presence" history).
5. Fully fingerprints only devices that are **new** or **still unidentified**: at most 8 per pass, and an unidentified device is retried at most every 6 hours, so fragile IoT gear is not hammered.
6. Optionally shows a desktop notification for a new device it could not identify.

Passes never overlap (a lock file makes a second one skip itself). History older than 90 days is pruned.

## 1. Try one pass by hand

```bash
cd ~/Documents/amenhotep-home-network-mapper
.venv/bin/amenhotep watch
```

You should see `watch #N done: X online, Y new, Z fingerprinted`. Add `--notify` to get a desktop notification when a new unknown device appears. Raw sockets must be enabled for good results; check with `.venv/bin/amenhotep doctor`.

## 2. Run it automatically with a systemd user timer

Install (every 20 minutes; the minimum is 5):

```bash
cd ~/Documents/amenhotep-home-network-mapper && assets/install-timer.sh 20
```

This writes `amenhotep-watch.service` and `amenhotep-watch.timer` into `~/.config/systemd/user/`, then enables and starts the timer. It runs as you, not as root, and the first pass starts two minutes after boot or login.

Check that it is scheduled:

```bash
systemctl --user list-timers amenhotep-watch
```

See what the last pass did:

```bash
journalctl --user -u amenhotep-watch -n 20
```

Change the interval by running the install command again with another number of minutes.

Remove it:

```bash
cd ~/Documents/amenhotep-home-network-mapper && assets/install-timer.sh --remove
```

Pause it without removing:

```bash
systemctl --user stop amenhotep-watch.timer
```

Resume it:

```bash
systemctl --user start amenhotep-watch.timer
```

### Keep it running after you log out

User timers stop when you log out. To keep them running (for example on an always-on machine), enable lingering once:

```bash
loginctl enable-linger "$USER"
```

Desktop notifications still need a logged-in desktop session.

## 3. Read the results

```bash
.venv/bin/amenhotep presence              # who is online now, times seen, typical hours (last 7 days)
.venv/bin/amenhotep presence --days 30    # a longer window
.venv/bin/amenhotep presence --offline    # only devices missing from the latest check
```

Columns: **NOW** (online or OFFLINE in the latest check), **SEEN** (checks where the device answered out of all checks), **LAST** (when it was last seen), **TYPICALLY ONLINE** (hours when it was seen in at least half the checks; it needs a day or more of data to say anything).

In the GUI (`amenhotep-gui`): the Devices table has a **Status** column, each device has a **Presence** line in the detail panel, and the Scans tab offers a **watch** profile for a manual pass.

## Troubleshooting

| Symptom | What to do |
|---------|------------|
| `another watch/scan pass is still running; skipping` | Normal: a previous pass or a GUI scan holds the lock. It tries again next time. |
| Timer never fires | `systemctl --user list-timers amenhotep-watch`. If it is missing, run the install command again. After a logout it needs lingering (see above). |
| `nmap not found` in the journal | Install nmap (`sudo dnf install nmap`). |
| New devices are not fingerprinted well | Raw sockets are off. Run `amenhotep doctor` and follow its `setcap` hint. |
| No notification | Install `notify-send` (package `libnotify`) and run from a desktop session with `--notify`. |
| A device shows OFFLINE but is on | Some Wi-Fi devices sleep and miss ARP/ping. Check again at the next pass; shorter intervals catch more. |
| The project folder moved | Run the install command again so the timer points to the new path. |

See also: [QUICKSTART.md](QUICKSTART.md) for the first run, and [SECURITY.md](SECURITY.md) for how passes stay gentle on devices.

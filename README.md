# feed2imap

Based on the configuration files of [feed2imap](https://github.com/feed2imap/feed2imap),
I wanted to get more control since the cache file kept ruining with the ruby implementation.
This is my first approach based just in the configuration file.

## Requirements

- Python 3.X (3.8 tested)

## Installation

### Linux / Mac OS / *nix

  ```bash
  sudo python3 setup.py install
  ```

### Windows (using PowerShell)

  ```PowerShell
  & $(where.exe python).split()[0] setup.py install
  ```

## Usage

1. Create a feeds file in YAML format with the following syntax:

```yaml
default-email: feed-sender@domain.com
disable-ssl-verification: true
include-images: true
feeds:
- name: Slashdot RSS
  url: http://rss.slashdot.org/Slashdot/slashdot
  target: "imaps://username:password@server.domain.com/INBOX.Feeds.Technology.Slashdot" # The dot separate folders. You can also use IMAP without SSL using imap: as protocol at the begging.
  ```

1. Run:

  ```bash
  feed2imap.py [OPTIONS]
  ```

### Options

  ```
  --debug-level [CRITICAL|ERROR|WARNING|INFO|DEBUG|NOTSET] Debug level.
  -f, --feeds-file TEXT           File in YAML with the information of the feeds.
  -l, --log-file TEXT             File to store all log information.
  -e, --default-email TEXT        Email address for the sender of the feed items.
  -n, --disable-ssl-verification  Disable SSL verification for the IMAP server certificate.
  -i, --include-images            Include images from feed items.
  -f, --feeds TEXT                Feed item in JSON format.
  -c, --cache-file TEXT           Cache file to store downloaded items.
  --help                          Show this message and exit.
  ```

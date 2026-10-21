# Windows timezone mapping

`windowsZones.xml` is the unmodified Unicode CLDR 48.2 supplemental Windows
timezone map, pinned to the immutable `unicode-org/cldr` tag
`release-48-2`:

- Source: https://raw.githubusercontent.com/unicode-org/cldr/release-48-2/common/supplemental/windowsZones.xml
- CLDR release record: https://cldr.unicode.org/index/downloads
- SHA-256: `9cf3db6a31fb382fee21b70be6feba1e82766b0fcd06e6261fb7936a73e537ff`
- Copyright and terms: https://www.unicode.org/copyright.html

The data file retains its original Unicode copyright and terms notice. The
resolver reads territory `001` from the XML at runtime; no Windows/IANA pairs
are typed into Python. It reads the selected TZif file directly from the pinned
`tzdata` package on every platform, so host operating-system timezone updates
cannot silently change a conversion. Each recorded host-zone entry carries the
tzdata version and the exact TZif SHA-256 used for that zone.

# The advisory file

`l2check/data/advisories.json` backs CFG03. It ships empty, and that is
deliberate: an advisory file with invented entries would make the check report
findings that are not true. With no entry for a detected model, CFG03 reports
`UNTESTED` with reason `no advisory data`, which is the honest answer and is
distinct from "this device is fine".

Runs never fetch anything. The file is read from disk, so a run is offline and
reproducible, and two runs a month apart compare against the same data unless
you deliberately updated it.

## Schema

```json
{
  "schema": 1,
  "updated": "2026-09-03",
  "source": "where you got this",
  "entries": [
    {
      "model": "substring matched against the detected model, case insensitive",
      "affected_firmware": ["substrings; an empty list means all versions"],
      "identifier": "CVE-0000-00000 or a vendor bulletin reference",
      "severity": "HIGH",
      "summary": "one line, in your own words",
      "fixed_in": "the first version that is not affected"
    }
  ]
}
```

`model` and `affected_firmware` are substring matches against what CFG01 or the
L3A04 banner reported, so `"Archer C7"` matches a detected `"TP-Link Archer C7 v2"`.

## Filling it in

Where to get the data, in rough order of usefulness for consumer gear:

- The vendor's own security bulletin page for your exact model.
- The NVD keyword search for the model name.
- The firmware release notes, which often describe fixes without an identifier.

Write the `summary` in your own words. A one line description you understand is
worth more in a report than a pasted CVE title.

## Installing an update

```
./bin/update-advisories path/to/advisories.json
```

It validates the schema, reports how many entries it holds, and installs it. It
refuses a file that does not parse or that is missing required fields, so a bad
edit cannot silently disable the check.

# Changelog

## Unreleased

### Fixes

Windows sensor scratch usage inspection now supports ordinary storage paths longer than 260 characters, including alternate streams on directories and files. Long OMGS_HOME paths no longer cause stream inspection to cancel scans and discard their output. Private storage creation and test ACL updates share the same path conversion at direct Win32 API boundaries; recorded paths and existing ownership, reparse point and usage limit checks retain their behavior.

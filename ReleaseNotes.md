<img align="right" width="250" height="47" src="Gematik_Logo_Flag_With_Background.png" /> <br />     

# Release Notes tiger-mail-extension

## Release 4.3.3

### Bugfixes

* TGRMAIL-6: Fix situation when POP3 AUTH response overtakes AUTH command.
  Also allow trailing whitespace in LIST/STAT response headers.

### Features

* TGR-2174: remove routing errors from POP3/SMTP connections

## Release 4.1.12

### Features

* TGR-1995: add automatic release pipeline triggered from tiger pipeline

## Release 4.1.11

* Update to tiger 4.1.1

## Release 4.0.10

### changed

- first release of tiger-mail-extension as standalone module. Older releases were a submodule of the [tiger project](https://github.com/gematik/app-Tiger). No new functionality was added.
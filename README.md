GNU Make for Windows
====================

[GNU Make](https://www.gnu.org/software/make/) can be built directly for Windows from the [GNU Git repository](https://savannah.gnu.org/git/?group=make).
This repo contains a few small adjustments.

## Prerequisites

* Visual Studio with C/C++ installed
* sed

## Changes

All changes are on the [4.3-win branch](https://github.com/toddlucas/make-win/tree/4.3-win), branched from the [4.3 tag](https://github.com/toddlucas/make-win/tree/4.3).

### 1. bootstrap

GNU Make now depends on a couple of files from the gnulib portability library.
These changes can be retrieved by running the `bootstrap` script (`bootstrap.bat` on Windows).
This branch directly adds those files, to simplify any required patching.

### 2. patches

Most of these patches are from [Michael M. Builov's](https://github.com/mbuilov) [gnumake-windows](https://github.com/mbuilov/gnumake-windows) project.
Adding them here as commits allows rebasing or cherry picking over to new branches as the base project is updated.

## Build

`build_w32.bat --without-guile`

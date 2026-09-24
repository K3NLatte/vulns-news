// Package npm profiles npm package manifests and npm lockfiles without
// invoking npm, running lifecycle scripts, or executing repository code.
//
// package.json and package-lock.json lockfile versions 2 and 3 are supported.
// pnpm and Yarn manifests and lockfiles are intentionally unsupported; callers
// should use separate ecosystem adapters for pnpm-lock.yaml and yarn.lock.
package npm

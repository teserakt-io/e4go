package e4common

/*

This file implements basic configuration helpers that all our go projects can
use. This might not be the right place for it, but it is going here for now.

We have some questions with regards to config files:

 1. How do we locate the actual configuration file (independent of whether
	viper is used)?
 2. How do we locate files specified as relative paths in the configuration file.

The deployment layout should look like this:

   /opt/e4/bin/binary
   /opt/e4/configs/projectconf.yaml
   /opt/e4/configs/sslcert.pem
   /opt/e4/share/e4/projectconf.yaml.template

and so on. /opt/e4 is an arbitrary (but reasonable) prefix that users may
decide to change, e.g. to /usr/local. As such:

 1. The config file should be located at ../configs/name.yaml relative to
	the binary.
 2. Additional configuration data is likely located in the configs directory
	too. So relative paths for such loads should be relative to the config
	file location.

In development, we have paths that look like this:

	GITREPO/bin/binary
	GITREPO/configs/projectconf.yaml

etc. So this logic works both for development and for production scenarios.
*/

import (
	"path/filepath"
)

// AppPathResolver represents the state of an application path lookup for future use
type AppPathResolver struct {
	binarypath         string
	absolutePrefixPath string
}

// This function finds the binary path from the argv[0]
func (a *AppPathResolver) binarydir() string {
	dir, _ := filepath.Abs(filepath.Dir(a.binarypath))
	return dir
}

// NewAppPathResolver returns a new instance of the AppPathResolver
func NewAppPathResolver() *AppPathResolver {
	a := AppPathResolver{}
	return &a
}

// Initialize initializes the resolver so that we can find future paths
func (a *AppPathResolver) Initialize(argv []string) {
	a.binarypath = argv[0]
	bindir := a.binarydir()
	a.absolutePrefixPath = filepath.Dir(bindir)
}

// ConfigFile returns the path to the config file, given conffilename as a config file argument
func (a *AppPathResolver) ConfigFile(conffilename string) string {
	return filepath.Join(filepath.Join(a.absolutePrefixPath, "configs"), conffilename)
}

// ConfigDir returns the path to the config file directory, given conffilename as a config file argument
func (a *AppPathResolver) ConfigDir() string {
	return filepath.Join(a.absolutePrefixPath, "configs")
}

// BinaryFile returns the path to the binary itself, in case this is ever useful
func (a *AppPathResolver) BinaryFile() string {
	return a.binarypath
}

// ConfigRelativePath resolves a relative filepath from the config file. If the filepath is
// absolute then it is returned unchanged. This is suitable to be called
// for all file resolutions
func (a *AppPathResolver) ConfigRelativePath(relpath string) string {
	if filepath.IsAbs(relpath) {
		return relpath
	}
	return filepath.Join(filepath.Join(a.absolutePrefixPath, "configs"), relpath)
}

package e4common

import (
	"testing"
)

func TestResolver(t *testing.T) {

	devArgv := []string{"/home/teserakt/dev/backend/bin/c2backend", "-somearg", "-someotherarg"}
	devConfigName := "c2.yaml"
	devConfigPath := "/home/teserakt/dev/backend/configs/" + devConfigName
	devSameDirRelPath := "ssl_cert.pem"
	devSameDirAbsPath := "/home/teserakt/dev/backend/configs/ssl_cert.pem"
	devDiffDirRelPath := "../share/l18n.db"
	devDiffDirAbsPath := "/home/teserakt/dev/backend/share/l18n.db"

	var devResolver AppPathResolver

	devResolver.Initialize(devArgv)

	if devResolver.BinaryFile() != devArgv[0] {
		t.Fatalf("Binary path was changed and should not have been")
	}

	if devResolver.ConfigFile(devConfigName) != devConfigPath {
		t.Fatalf("Relative path of config file did not resolve correctly")
	}

	if devResolver.ConfigRelativePath(devSameDirRelPath) != devSameDirAbsPath {
		t.Fatalf("Same directory lookup of file relative to config path did not succeed")
	}

	if devResolver.ConfigRelativePath(devDiffDirRelPath) != devDiffDirAbsPath {
		t.Fatalf("Same directory lookup of file relative to config path did not succeed")
	}

	prodArgv := []string{"/opt/teserakt/e4/bin/c2backend", "-somearg", "-someotherarg"}
	prodConfigName := "c2.yaml"
	prodConfigPath := "/opt/teserakt/e4/configs/" + prodConfigName
	prodSameDirRelPath := "ssl_cert.pem"
	prodSameDirAbsPath := "/opt/teserakt/e4/configs/ssl_cert.pem"
	prodDiffDirRelPath := "../share/l18n.db"
	prodDiffDirAbsPath := "/opt/teserakt/e4/share/l18n.db"

	var prodResolver AppPathResolver

	prodResolver.Initialize(prodArgv)

	if prodResolver.BinaryFile() != prodArgv[0] {
		t.Fatalf("Binary path was changed and should not have been")
	}

	if prodResolver.ConfigFile(prodConfigName) != prodConfigPath {
		t.Fatalf("Relative path of config file did not resolve correctly")
	}

	if prodResolver.ConfigRelativePath(prodSameDirRelPath) != prodSameDirAbsPath {
		t.Fatalf("Same directory lookup of file relative to config path did not succeed")
	}

	if prodResolver.ConfigRelativePath(prodDiffDirRelPath) != prodDiffDirAbsPath {
		t.Fatalf("Same directory lookup of file relative to config path did not succeed")
	}

}

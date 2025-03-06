package goefs

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestCreateOpenVault(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.goe")

	vault, err := CreateVault("password", vaultPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()

	vault2, err := OpenVault("password", vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer vault2.Close()
}

func TestSaveReadDeleteFile(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.goe")

	vault, err := CreateVault("password", vaultPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()

	data := []byte("This is a test file")
	fileID, err := vault.SaveFile(data)
	if err != nil {
		t.Fatal(err)
	}

	readData, err := vault.ReadFile(fileID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, readData) {
		t.Fatal("Read data does not match original")
	}

	if err := vault.DeleteFile(fileID); err != nil {
		t.Fatal(err)
	}

	_, err = vault.ReadFile(fileID)
	if err == nil {
		t.Fatal("Expected error reading deleted file")
	}
}

func TestVaultDefragmentation(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.goe")

	vault, err := CreateVault("password", vaultPath, 4096)
	if err != nil {
		t.Fatal(err)
	}

	data1 := []byte("File One")
	data2 := []byte("File Two")
	id1, _ := vault.SaveFile(data1)
	id2, _ := vault.SaveFile(data2)
	vault.DeleteFile(id1)
	vault.Close()

	vault, err = OpenVault("password", vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()

	readData, err := vault.ReadFile(id2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data2, readData) {
		t.Fatal("Data corrupted after defragmentation")
	}
}

func TestListIDs(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.goe")

	vault, err := CreateVault("password", vaultPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()

	data := []byte("Test file")
	id, err := vault.SaveFile(data)
	if err != nil {
		t.Fatal(err)
	}

	ids, err := vault.ListIDs()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, fid := range ids {
		if fid == id {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("File ID not found in list")
	}
}

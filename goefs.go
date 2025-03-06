// Package goefs implements an encrypted file system vault.
// Files are stored in fixed-size encrypted blocks within a single vault file.
// A small unencrypted header contains basic vault parameters.
// Blocks 0 .. (MetadataBlockCount-1) are reserved for encrypted metadata.
// Files smaller than a block are padded; larger files are split across blocks.
// The vault defragments itself in-place upon close.
// Reading is safe for concurrent access, while saving/deleting is synchronized.
package goefs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"

	"github.com/google/uuid"
)

const (
	// Magic string to identify a valid vault.
	Magic      = "GOEFS"
	Version    = uint16(1)
	HeaderSize = 32 // Size of the unencrypted header in bytes.
)

// fileNamespace is a fixed namespace used to compute file IDs as a hash of the file content.
var fileNamespace = uuid.MustParse("1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d")

// Vault represents an open encrypted file system vault.
type Vault struct {
	mu             sync.RWMutex
	file           *os.File
	key            []byte // Derived from the password.
	blockSize      int
	metadataBlocks int // Number of blocks reserved for metadata.
	metadata       Metadata
}

// Metadata holds the vault metadata stored in blocks 0..(metadataBlocks-1).
type Metadata struct {
	// Files maps a file's UUID (string form) to its metadata.
	Files map[string]FileEntry
	// FreeBlocks holds indices of blocks available for reuse.
	FreeBlocks []int
	// NextBlock is the next new block index for file data (should be >= metadataBlocks).
	NextBlock int
}

// FileEntry holds the metadata for a file stored in the vault.
type FileEntry struct {
	// Blocks lists the block indices where the file's data is stored.
	Blocks []int
	// Size is the original file size (before padding).
	Size int
}

// Header represents the unencrypted header stored at the start of the vault file.
type Header struct {
	Magic              [5]byte // "GOEFS"
	Version            uint16  // e.g. 1
	BlockSize          uint32  // block size in bytes
	MetadataBlock      uint32  // starting block index for metadata (always 0)
	MetadataBlockCount uint32  // number of blocks reserved for metadata
	// The rest is reserved/padding.
}

// deriveKey returns an AES-256 key derived from the provided password.
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// createIV returns a deterministic IV for a given block index.
// We encode the block index (8 bytes, big-endian) into the first 8 bytes of a 16-byte IV.
func createIV(blockIndex int) []byte {
	iv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint64(iv, uint64(blockIndex))
	// Remaining 8 bytes are zeros.
	return iv
}

// encryptBlock encrypts a plaintext block using AES-CTR with a deterministic IV.
func encryptBlock(key []byte, blockIndex int, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := createIV(blockIndex)
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// decryptBlock decrypts a ciphertext block using AES-CTR with a deterministic IV.
func decryptBlock(key []byte, blockIndex int, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := createIV(blockIndex)
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// writeHeader writes the unencrypted header at the start of the vault file.
func writeHeader(f *os.File, blockSize int, metadataBlockCount int) error {
	var h Header
	copy(h.Magic[:], []byte(Magic))
	h.Version = Version
	h.BlockSize = uint32(blockSize)
	h.MetadataBlock = 0
	h.MetadataBlockCount = uint32(metadataBlockCount)

	buf := make([]byte, HeaderSize)
	copy(buf[0:5], h.Magic[:])
	binary.BigEndian.PutUint16(buf[5:7], h.Version)
	binary.BigEndian.PutUint32(buf[7:11], h.BlockSize)
	binary.BigEndian.PutUint32(buf[11:15], h.MetadataBlock)
	binary.BigEndian.PutUint32(buf[15:19], h.MetadataBlockCount)
	// The rest of the header is padding.
	_, err := f.WriteAt(buf, 0)
	return err
}

// readHeader reads the unencrypted header from the vault file.
func readHeader(f *os.File) (Header, error) {
	var h Header
	buf := make([]byte, HeaderSize)
	_, err := f.ReadAt(buf, 0)
	if err != nil {
		return h, err
	}
	copy(h.Magic[:], buf[0:5])
	if string(h.Magic[:]) != Magic {
		return h, errors.New("invalid vault file: magic mismatch")
	}
	h.Version = binary.BigEndian.Uint16(buf[5:7])
	h.BlockSize = binary.BigEndian.Uint32(buf[7:11])
	h.MetadataBlock = binary.BigEndian.Uint32(buf[11:15])
	h.MetadataBlockCount = binary.BigEndian.Uint32(buf[15:19])
	return h, nil
}

// blockOffset returns the file offset for a given block index.
func blockOffset(blockIndex, blockSize int) int64 {
	return int64(HeaderSize + blockIndex*blockSize)
}

// readBlock reads and decrypts the block at the given block index.
func readBlock(f *os.File, key []byte, blockIndex int, blockSize int) ([]byte, error) {
	buf := make([]byte, blockSize)
	offset := blockOffset(blockIndex, blockSize)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != blockSize {
		return nil, fmt.Errorf("could not read full block: expected %d bytes, got %d", blockSize, n)
	}
	return decryptBlock(key, blockIndex, buf)
}

// writeBlock encrypts and writes the given data to the specified block index.
func writeBlock(f *os.File, key []byte, blockIndex int, blockSize int, data []byte) error {
	if len(data) != blockSize {
		return fmt.Errorf("data length %d does not match block size %d", len(data), blockSize)
	}
	encrypted, err := encryptBlock(key, blockIndex, data)
	if err != nil {
		return err
	}
	offset := blockOffset(blockIndex, blockSize)
	_, err = f.WriteAt(encrypted, offset)
	return err
}

// loadMetadata reads and deserializes the vault metadata from the metadata region.
// It reads all metadata blocks, concatenates their decrypted contents,
// trims trailing zeros, and unmarshals the JSON.
func (v *Vault) loadMetadata() error {
	var combined []byte
	for i := 0; i < v.metadataBlocks; i++ {
		blockData, err := readBlock(v.file, v.key, i, v.blockSize)
		if err != nil {
			return err
		}
		combined = append(combined, blockData...)
	}
	combined = bytes.TrimRight(combined, "\x00")
	if len(combined) == 0 {
		v.metadata = Metadata{
			Files:      make(map[string]FileEntry),
			FreeBlocks: []int{},
			NextBlock:  v.metadataBlocks, // File data starts after metadata region.
		}
		return nil
	}
	var m Metadata
	if err := json.Unmarshal(combined, &m); err != nil {
		return err
	}
	v.metadata = m
	return nil
}

// saveMetadata serializes and writes the vault metadata across the metadata region.
// If the metadata no longer fits in the currently allocated blocks, it expands the metadata region.
func (v *Vault) saveMetadata() error {
	data, err := json.Marshal(v.metadata)
	if err != nil {
		return err
	}
	requiredBlocks := (len(data) + v.blockSize - 1) / v.blockSize
	if requiredBlocks > v.metadataBlocks {
		if err := v.expandMetadataRegion(requiredBlocks); err != nil {
			return err
		}
	}
	// Prepare a buffer of size = metadataBlocks * blockSize.
	totalSize := v.metadataBlocks * v.blockSize
	buf := make([]byte, totalSize)
	copy(buf, data) // remaining bytes are zeros (padding)
	// Write the data into each metadata block.
	for i := 0; i < v.metadataBlocks; i++ {
		start := i * v.blockSize
		end := start + v.blockSize
		chunk := buf[start:end]
		if err := writeBlock(v.file, v.key, i, v.blockSize, chunk); err != nil {
			return err
		}
	}
	return nil
}

// expandMetadataRegion expands the metadata region to newCount blocks.
// It shifts all file data blocks upward to make room and updates metadata accordingly.
func (v *Vault) expandMetadataRegion(newCount int) error {
	oldCount := v.metadataBlocks
	if newCount <= oldCount {
		return nil
	}
	delta := newCount - oldCount

	// Shift file data blocks upward.
	// File data blocks range from index = oldCount to v.metadata.NextBlock - 1.
	for i := v.metadata.NextBlock - 1; i >= oldCount; i-- {
		data, err := readBlock(v.file, v.key, i, v.blockSize)
		if err != nil {
			return err
		}
		newIndex := i + delta
		if err := writeBlock(v.file, v.key, newIndex, v.blockSize, data); err != nil {
			return err
		}
	}

	// Update file entries: shift block indices >= oldCount.
	for k, entry := range v.metadata.Files {
		newBlocks := make([]int, len(entry.Blocks))
		for i, blk := range entry.Blocks {
			if blk >= oldCount {
				newBlocks[i] = blk + delta
			} else {
				newBlocks[i] = blk
			}
		}
		v.metadata.Files[k] = FileEntry{Blocks: newBlocks, Size: entry.Size}
	}

	// Update free blocks similarly.
	for i, blk := range v.metadata.FreeBlocks {
		if blk >= oldCount {
			v.metadata.FreeBlocks[i] = blk + delta
		}
	}

	// Update NextBlock.
	v.metadata.NextBlock += delta

	// Update the metadata region size.
	v.metadataBlocks = newCount
	if err := writeHeader(v.file, v.blockSize, v.metadataBlocks); err != nil {
		return err
	}

	return nil
}

// CreateVault creates a new vault file at filePath using the given password and blockSize.
// The initial metadata region is allocated as 1 block.
// It returns an error if the vault file already exists.
func CreateVault(password, filePath string, blockSize int) (*Vault, error) {
	key := deriveKey(password)
	// Use os.O_EXCL to ensure we do not overwrite an existing file.
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	// Set initial metadata region to 1 block.
	initialMetadataBlocks := 1
	if err := writeHeader(file, blockSize, initialMetadataBlocks); err != nil {
		file.Close()
		return nil, err
	}
	// Initialize an empty metadata block.
	metadata := Metadata{
		Files:      make(map[string]FileEntry),
		FreeBlocks: []int{},
		NextBlock:  initialMetadataBlocks, // File data starts after metadata region.
	}
	v := &Vault{
		file:           file,
		key:            key,
		blockSize:      blockSize,
		metadataBlocks: initialMetadataBlocks,
		metadata:       metadata,
	}
	if err := v.saveMetadata(); err != nil {
		file.Close()
		return nil, err
	}
	return v, nil
}

// OpenVault opens an existing vault file at filePath using the provided password.
// It retrieves the block size and metadata region size from the vault header.
func OpenVault(password, filePath string) (*Vault, error) {
	key := deriveKey(password)
	file, err := os.OpenFile(filePath, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	h, err := readHeader(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	v := &Vault{
		file:           file,
		key:            key,
		blockSize:      int(h.BlockSize),
		metadataBlocks: int(h.MetadataBlockCount),
	}
	if err := v.loadMetadata(); err != nil {
		file.Close()
		return nil, err
	}
	return v, nil
}

// SaveFile saves the provided file data into the vault.
// It splits the file into blocks (padding the last block if necessary).
// The file ID is computed as a SHA-1–based UUID from the file content.
// If a file with the same content already exists, an error is returned.
func (v *Vault) SaveFile(data []byte) (uuid.UUID, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Compute file id as a SHA-1–based UUID using a fixed namespace.
	id := uuid.NewSHA1(fileNamespace, data)
	if _, exists := v.metadata.Files[id.String()]; exists {
		return uuid.Nil, fmt.Errorf("file already exists (duplicate)")
	}

	numBlocks := (len(data) + v.blockSize - 1) / v.blockSize
	blocks := make([]int, numBlocks)

	for i := 0; i < numBlocks; i++ {
		var blockIndex int
		if len(v.metadata.FreeBlocks) > 0 {
			blockIndex = v.metadata.FreeBlocks[0]
			v.metadata.FreeBlocks = v.metadata.FreeBlocks[1:]
		} else {
			blockIndex = v.metadata.NextBlock
			v.metadata.NextBlock++
		}
		blocks[i] = blockIndex

		start := i * v.blockSize
		end := start + v.blockSize
		if end > len(data) {
			end = len(data)
		}
		blockData := make([]byte, v.blockSize)
		copy(blockData, data[start:end])
		if err := writeBlock(v.file, v.key, blockIndex, v.blockSize, blockData); err != nil {
			return uuid.Nil, err
		}
	}

	v.metadata.Files[id.String()] = FileEntry{
		Blocks: blocks,
		Size:   len(data),
	}
	if err := v.saveMetadata(); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// ReadFile reads and returns the file data corresponding to the given UUID.
func (v *Vault) ReadFile(id uuid.UUID) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, exists := v.metadata.Files[id.String()]
	if !exists {
		return nil, errors.New("file not found")
	}
	data := make([]byte, 0, entry.Size)
	for _, blockIndex := range entry.Blocks {
		blockData, err := readBlock(v.file, v.key, blockIndex, v.blockSize)
		if err != nil {
			return nil, err
		}
		data = append(data, blockData...)
	}
	return data[:entry.Size], nil
}

// DeleteFile removes the file with the given UUID from the vault.
// Its blocks are marked free for reuse.
func (v *Vault) DeleteFile(id uuid.UUID) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	entry, exists := v.metadata.Files[id.String()]
	if !exists {
		return errors.New("file not found")
	}
	v.metadata.FreeBlocks = append(v.metadata.FreeBlocks, entry.Blocks...)
	delete(v.metadata.Files, id.String())
	return v.saveMetadata()
}

// ListIDs returns a slice of all file IDs stored in the vault.
func (v *Vault) ListIDs() ([]uuid.UUID, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	ids := make([]uuid.UUID, 0, len(v.metadata.Files))
	for idStr := range v.metadata.Files {
		id, err := uuid.Parse(idStr)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// defragment compacts file data blocks to be contiguous starting at block index = metadataBlocks.
// It reads blocks that need to be moved, writes them to new contiguous positions, updates metadata,
// and truncates the vault file.
func (v *Vault) defragment() error {
	currentBlock := v.metadataBlocks // start after metadata
	newFiles := make(map[string]FileEntry)

	for fileID, fileEntry := range v.metadata.Files {
		var fileData []byte

		// Read the full file data
		for _, blockIndex := range fileEntry.Blocks {
			blockData, err := readBlock(v.file, v.key, blockIndex, v.blockSize)
			if err != nil {
				return fmt.Errorf("error reading block %d: %w", blockIndex, err)
			}
			fileData = append(fileData, blockData...)
		}

		// Trim padding
		fileData = fileData[:fileEntry.Size]

		// Split into blocks and write
		numBlocks := int(math.Ceil(float64(len(fileData)) / float64(v.blockSize)))
		newBlockIndices := make([]int, numBlocks)

		for i := 0; i < numBlocks; i++ {
			start := i * v.blockSize
			end := start + v.blockSize
			if end > len(fileData) {
				end = len(fileData)
			}
			chunk := fileData[start:end]

			// Pad last block if needed
			if len(chunk) < v.blockSize {
				padding := make([]byte, v.blockSize-len(chunk))
				chunk = append(chunk, padding...)
			}

			if err := writeBlock(v.file, v.key, currentBlock, v.blockSize, chunk); err != nil {
				return fmt.Errorf("error writing block %d: %w", currentBlock, err)
			}

			newBlockIndices[i] = currentBlock
			currentBlock++
		}

		// Update file entry
		newFiles[fileID] = FileEntry{
			Size:   fileEntry.Size,
			Blocks: newBlockIndices,
		}
	}

	v.metadata.Files = newFiles
	v.metadata.FreeBlocks = []int{}
	v.metadata.NextBlock = currentBlock

	if err := v.saveMetadata(); err != nil {
		return fmt.Errorf("error saving metadata after defragmentation: %w", err)
	}

	// Truncate the file to remove any leftover data from previous larger states
	expectedSize := int64(v.metadata.NextBlock) * int64(v.blockSize)
	if err := v.file.Truncate(expectedSize); err != nil {
		return fmt.Errorf("error truncating vault file: %w", err)
	}

	return nil
}

// Close defragments the vault in-place and closes the underlying file.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.defragment(); err != nil {
		return err
	}
	return v.file.Close()
}

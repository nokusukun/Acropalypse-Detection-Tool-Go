package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const PNG_MAGIC = "\x89PNG\r\n\x1a\n"

func parsePNGChunk(r io.Reader) (string, []byte, error) {
	var size uint32
	err := binary.Read(r, binary.BigEndian, &size)
	if err != nil {
		return "", nil, err
	}

	ctype := make([]byte, 4)
	_, err = r.Read(ctype)
	if err != nil {
		return "", nil, err
	}

	body := make([]byte, size)
	_, err = r.Read(body)
	if err != nil {
		return "", nil, err
	}

	var csum uint32
	err = binary.Read(r, binary.BigEndian, &csum)
	if err != nil {
		return "", nil, err
	}

	if crc32.ChecksumIEEE(append(ctype, body...)) != csum {
		return "", nil, fmt.Errorf("crc32 check failed")
	}

	return string(ctype), body, nil
}

func validIEND(trailer []byte) bool {
	iendPos := len(trailer) - 8
	iendSize := binary.BigEndian.Uint32(trailer[iendPos-4 : iendPos])
	iendCsum := binary.BigEndian.Uint32(trailer[iendPos+4 : iendPos+8])
	return iendSize == 0 && iendCsum == 0xAE426082
}

func is_fucked(path string) (bool, error) {
	if len(os.Args) != 2 {
		fmt.Printf("USAGE: %s cropped.png\n", os.Args[0])
		os.Exit(1)
	}

	fIn, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer fIn.Close()

	magic := make([]byte, len(PNG_MAGIC))
	_, err = fIn.Read(magic)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(magic, []byte(PNG_MAGIC)) {
		return false, err
	}

	for {
		ctype, _, err := parsePNGChunk(fIn)
		if err != nil {
			return false, err
		}
		if ctype == "IEND" {
			break
		}
	}

	trailer := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := fIn.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		trailer = append(trailer, buf[:n]...)
	}

	return len(trailer) > 0 && validIEND(trailer), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: acropalypse_detector <directory/file>")
		os.Exit(1)
	}

	dir := os.Args[1]

	fi, err := os.Stat(dir)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if fi.Mode().IsRegular() {
		if !strings.HasSuffix(strings.ToLower(dir), ".png") {
			return
		}

		fmt.Printf("Check: '%v'\n", dir)
		fucked, _ := is_fucked(dir)
		if fucked {
			fmt.Printf("Result: '%v' is vulnerable\n", dir)
		}
		return
	}

	var vulnerableFiles []string
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}

		if info.Mode().IsRegular() {
			if !strings.HasSuffix(strings.ToLower(path), ".png") {
				return nil
			}

			fmt.Printf("Check: '%v'\n", path)
			fucked, _ := is_fucked(path)
			if fucked {
				fmt.Printf("Result: '%v' is vulnerable\n", path)
				vulnerableFiles = append(vulnerableFiles, path)
			}
		}

		return nil
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("\n-- Vulnerable Images [%v] --\n", len(vulnerableFiles))
	for _, file := range vulnerableFiles {
		fmt.Println(file)
	}
}

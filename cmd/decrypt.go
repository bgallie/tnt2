/*
Copyright © 2021 Billy G. Allie <bill.allie@defiant.mug.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/bgallie/filters/ascii85"
	"github.com/bgallie/filters/flate"
	"github.com/bgallie/filters/lines"
	"github.com/bgallie/filters/pem"
	"github.com/bgallie/tntengine"
	"github.com/spf13/cobra"
)

var (
	bytesRemaining int64
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a TNT2 encrypted file.",
	Long:  `Decrypt a file encrypted by the TNT2 Infinite (with respect to the plaintext) Key Encryption System.`,
	Run: func(cmd *cobra.Command, args []string) {
		decrypt(args)
	},
}

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:        "decode",
	Short:      "Decode a TNT2 encoded file.",
	Long:       `[DEPRECATED] Decode a file encoded by the TNT2 Infinite (with respect to the plaintext) Key Encryption System.`,
	Deprecated: "use \"decrypt\" instead.",
	Run: func(cmd *cobra.Command, args []string) {
		decrypt(args)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(decodeCmd)
}

// fromBinaryHelper provides the neams to inject the pure binary input
// into the pipe stream used by the decrypt() function.  The data can
// be read using the returned PipeReader.
func fromBinaryHelper(rdr io.Reader) *io.PipeReader {
	rRdr, rWrtr := io.Pipe()
	wg.Add(1)
	go func() {
		defer rWrtr.Close()
		defer wg.Done()
		_, err := io.Copy(rWrtr, rdr)
		checkError(err)
	}()
	return rRdr
}

func decrypt(args []string) {
	initEngine(args)

	// Set the engine type and build the cipher machine.
	tntMachine.SetEngineType("D")
	tntMachine.BuildCipherMachine()
	fin, fout := getInputAndOutputFiles(false)
	defer fout.Close()
	var fal string
	var ofName string
	var bRdr *bufio.Reader
	var pRdr *io.PipeReader
	var exists bool
	var err error
	bRdr = bufio.NewReader(fin)
	b, err := bRdr.Peek(5)
	checkError(err)
	if string(b) == "-----" {
		usePem = true
		var blck pem.Block
		pRdr, blck = pem.FromPem(bRdr)
		fal, exists = blck.Headers["ApiLevel"]
		if !exists {
			fal = "-1"
		}
		iCnt, _ = new(big.Int).SetString(blck.Headers["Counter"], 10)
		if len(outputFileName) == 0 {
			fname, ok := blck.Headers["FileName"]
			if ok {
				ofName = fname
			}
		}
		cmpr, ok := blck.Headers["Compression"]
		if ok {
			compression = cmpr == "true"
		}
		_, err = fmt.Sscanf(blck.Headers["FileSize"], "%d", &bytesRemaining)
	} else {
		line, err := bRdr.ReadString('\n')
		if err == nil {
			fields := strings.Split(line[:len(line)-1], "|")
			switch len(fields) {
			case 1:
				ofName = ""
				iCnt, _ = new(big.Int).SetString(fields[0], 10)
			case 2:
				ofName = fields[0]
				iCnt, _ = new(big.Int).SetString(fields[1], 10)
			case 6:
				fal = "-1"
			case 7:
				fal = fields[1]
				ofName = fields[2]
				useASCII85 = fields[3] == "a"
				useBinary = fields[3] == "b"
				compression = fields[4] == "true"
				iCnt, _ = new(big.Int).SetString(fields[5], 10)
				_, err = fmt.Sscanf(fields[6], "%d", &bytesRemaining)
				checkError(err)
			}
		}
	}

	fileApiLevel, _ := strconv.Atoi(fal)
	if fileApiLevel != tnt2ApiLevel {
		fmt.Fprintf(os.Stderr, "Error: API Level mismatch. FileApiLevel: %d, Tnt2ApiLevel: %d\n", fileApiLevel, tnt2ApiLevel)
		os.Exit(100)
	}

	if len(outputFileName) == 0 {
		if len(ofName) > 0 {
			var err error
			fout, err = os.Create(ofName)
			checkError(err)
		}
	}

	tntMachine.SetIndex(iCnt)
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	decRdr, decWrtr := io.Pipe()
	err = nil
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer decWrtr.Close()
		var cnt int
		encText := make([]byte, 0)
		var aRdr *io.PipeReader

		if usePem {
			aRdr = pRdr
		} else if useASCII85 {
			aRdr = ascii85.FromASCII85(lines.CombineLines(bRdr))
		} else {
			aRdr = fromBinaryHelper(bRdr)
		}

		for err != io.EOF {
			b := make([]byte, 1024)
			cnt, err = aRdr.Read(b)
			checkError(err)
			if err != io.EOF {
				encText = append(encText, b[:cnt]...)
				for len(encText) >= tntengine.CypherBlockBytes {
					blk := *new(tntengine.CypherBlock)
					blk.Length = int8(tntengine.CypherBlockBytes)
					_ = copy(blk.CypherBlock[:], encText[:blk.Length])
					leftMost <- blk
					blk = <-rightMost
					var err1 error
					if bytesRemaining < int64(blk.Length) {
						_, err1 = decWrtr.Write(blk.CypherBlock[:bytesRemaining])
					} else {
						_, err1 = decWrtr.Write(blk.CypherBlock[:])
					}
					checkError(err1)
					bytesRemaining -= int64(blk.Length)
					pt := make([]byte, 0)
					pt = append(pt, encText[blk.Length:]...)
					encText = pt
				}
			}
		}
	}()

	var flateRdr *io.PipeReader = decRdr
	if compression {
		flateRdr = flate.FromFlate(decRdr)
	}

	_, err = io.Copy(fout, flateRdr)
	checkError(err)
	wg.Wait() // Wait for the decryption machine to finish it's clean up.
}

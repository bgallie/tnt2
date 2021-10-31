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
	"strings"
	"sync"

	"github.com/bgallie/filters/ascii85"
	"github.com/bgallie/filters/flate"
	"github.com/bgallie/filters/lines"
	"github.com/bgallie/filters/pem"
	"github.com/bgallie/tntengine"
	"github.com/spf13/cobra"
)

var (
	useASCII85   bool
	usePem       bool
	useBinary    bool
	compression  bool
	cnt          string = "-1"
	wg           sync.WaitGroup
	bytesWritten int64
	headerLine   string
)

// encodeCmd represents the encode command
var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode plaintext using TNT2",
	Long:  `Encode plaintext using the TNT2 Infinite Key (with respect to the plaintext) Encryption System.`,
	Run: func(cmd *cobra.Command, args []string) {
		useBinary = !(useASCII85 || usePem)
		encode(args)
	},
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	encodeCmd.Flags().BoolVarP(&useASCII85, "useASCII85", "a", false, "use ASCII85 encoding")
	encodeCmd.Flags().BoolVarP(&usePem, "usePem", "p", false, "use PEM encoding.")
	encodeCmd.Flags().BoolVarP(&compression, "compress", "c", false, "compress input file using flate")
	encodeCmd.Flags().StringVarP(&cnt, "count", "n", "-1", "initial block count")
}

func encode(args []string) {
	initEngine(args)

	// Get the starting block count.  cnt can be a number or a fraction such
	// as "1/2", "2/3", or "3/4".  If it is a fraction, then the starting block
	// count is calculated by multiplying the maximal states of the tntEngine
	// by the fraction.
	if cnt != "-1" {
		var good bool
		flds := strings.Split(cnt, "/")
		if len(flds) == 1 {
			iCnt, good = new(big.Int).SetString(cnt, 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the count to a big.Int: [%s]\n", cnt))
			}
		} else if len(flds) == 2 {
			m := new(big.Int).Set(tntMachine.MaximalStates())
			a, good := new(big.Int).SetString(flds[0], 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the numerator to a big.Int: [%s]\n", flds[0]))
			}
			b, good := new(big.Int).SetString(flds[1], 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the denominator to a big.Int: [%s]\n", flds[1]))
			}
			iCnt = m.Div(m.Mul(m, a), b)
		} else {
			cobra.CheckErr(fmt.Sprintf("Incorrect initial count: [%s]\n", cnt))
		}
	} else {
		iCnt = new(big.Int).Set(tntengine.BigZero)
	}

	// Set the engine type and build the cipher machine.
	tntMachine.SetEngineType("E")
	tntMachine.BuildCipherMachine()

	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encode the file.
	cMap = make(map[string]*big.Int)
	cMap = readCounterFile(cMap)
	mKey = tntMachine.CounterKey()
	if cMap[mKey] == nil {
		cMap[mKey] = iCnt
	} else {
		iCnt = cMap[mKey]
		if cnt != "-1" {
			fmt.Fprintln(os.Stderr, "Ignoring the block count argument - using the value from the .tnt2 file.")
		}
	}
	// Now we can set the index of the ciper machine.
	tntMachine.SetIndex(iCnt)

	var encIn *io.PipeReader
	// leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	fin, fout := getInputAndOutputFiles(true)
	var blck pem.Block
	if usePem { //useASCII85 || useBinary {
		blck.Headers = make(map[string]string)
		blck.Type = "TNT2 Encoded Message"
		blck.Headers["Counter"] = fmt.Sprintf("%s", tntMachine.Index())
		if len(inputFileName) > 0 && inputFileName != "-" {
			blck.Headers["FileName"] = inputFileName
		}
		blck.Headers["Compression"] = fmt.Sprintf("%v", compression)
	} else {
		headerLine = "+TNT2|"
		if len(inputFileName) > 0 && inputFileName != "-" {
			headerLine += inputFileName
		}
		if useASCII85 {
			headerLine += "|a"
		} else {
			headerLine += "|b"
		}
		headerLine += fmt.Sprintf("|%s|%s|", fmt.Sprintf("%v", compression), tntMachine.Index())
		fout.WriteString(headerLine)
	}

	if compression {
		encIn = toBinaryHelper(flate.ToFlate(fin))
	} else {
		encIn = toBinaryHelper(fin)
	}

	defer fout.Close()
	bRdr := bufio.NewReader(encIn)
	if useBinary {
		_, err := io.Copy(fout, bRdr)
		checkError(err)
	} else if useASCII85 {
		line, err := bRdr.ReadString('\n')
		checkError(err)
		_, err = fout.Write([]byte(line))
		checkError(err)
		_, err = io.Copy(fout, lines.SplitToLines(ascii85.ToASCII85(encIn)))
		checkError(err)
	} else {
		line, err := bRdr.ReadString('\n')
		checkError(err)
		blck.Headers["FileSize"] = line[:len(line)-1]
		_, err = io.Copy(fout, pem.ToPem(bRdr, blck))
		checkError(err)
	}
	wg.Wait()
	cMap[mKey] = tntMachine.Index()
	checkError(writeCounterFile(cMap))

}

// toBinaryHelper provides the means to output pure binary encrypted
// data to the output file along with the number of byte encrypted.
// This is necessary because then entire last block of encrypted data must
// be output in order to properly decrypt it, even if the plain text does
// not fill the final block.
func toBinaryHelper(rdr io.Reader) *io.PipeReader {
	rRdr, rWrtr := io.Pipe()
	var cnt int
	var err error
	var tmpFile *os.File
	plainText := make([]byte, 0)
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	tmpFile, err = os.CreateTemp("", "tnt2*")
	checkError(err)
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer os.Remove(tmpFile.Name())
		defer rWrtr.Close()
		err = nil

		for err != io.EOF {
			b := make([]byte, 2048)
			cnt, err = rdr.Read(b)
			checkError(err)

			if err != io.EOF {
				plainText = append(plainText, b[:cnt]...)
				for len(plainText) >= tntengine.CypherBlockBytes {
					blk := *new(tntengine.CypherBlock)
					blk.Length = tntengine.CypherBlockBytes
					_ = copy(blk.CypherBlock[:], plainText[:blk.Length])
					leftMost <- blk
					blk = <-rightMost
					cnt, err1 := tmpFile.Write(blk.CypherBlock[:])
					checkError(err1)
					bytesWritten += int64(cnt)
					pt := make([]byte, 0)
					pt = append(pt, plainText[blk.Length:]...)
					plainText = pt
				}
			}
		}

		if len(plainText) > 0 {
			blk := *new(tntengine.CypherBlock)
			blk.Length = int8(len(plainText))
			cnt = copy(blk.CypherBlock[:], plainText[:blk.Length])
			leftMost <- blk
			blk = <-rightMost
			_, err1 := tmpFile.Write(blk.CypherBlock[:])
			checkError(err1)
			bytesWritten += int64(blk.Length)
		}

		_, err = tmpFile.Seek(0, 0)
		checkError(err)
		rWrtr.Write([]byte(fmt.Sprintf("%d\n", bytesWritten)))
		_, err = io.Copy(rWrtr, tmpFile)
		checkError(err)
		// shutdown the decryption machine by processing a CypherBlock with zero
		// value length field.
		var blk tntengine.CypherBlock
		leftMost <- blk
		<-rightMost
	}()

	return rRdr
}

// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file for details.

// Package main -  tnt2 is an encryption system based on the article in
// Dr. Dobbs Journal Volume 9, Number 94, 1984 titled
// "An Infinite Key Encryption System" by John A. Thomas and Joan Thersites.
package main

import (
	"bufio"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/bgallie/filters/ascii85"
	"github.com/bgallie/filters/flate"
	"github.com/bgallie/filters/lines"
	"github.com/bgallie/filters/pem"
	"github.com/bgallie/tntengine"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	tnt2CountFile = ".tnt2"
	usage         = "tnt2 -d|-e [-c bigInt][-nc][-a][-pf proFormaFile][-if inputfile][-of outputfile]"
)

var (
	encode           bool // Flag: True to encode, False to decode
	decode           bool // Flag: True to decode, False to encode
	useASCII85       bool // Flag: True to using ascii85 encoding
	useBinary        bool // Flag: True to output pure binary (no encoding).
	noCompression    bool // Flag: True to not compress the file.
	tntMachine       tntengine.TntEngine
	iCnt             *big.Int
	cMap             map[string]*big.Int
	mKey             string
	cntrFileName     string
	inputFileName    string
	outputFileName   string
	proFormaFileName string
	proFormaFile     os.File
	perm             func(int) []byte
	intn             func(int) int
	inputFile        = os.Stdin
	outputFile       = os.Stdout
	bytesRemaining   int64
	bytesWritten     int64
	headerLine       string
	wg               sync.WaitGroup
)

func init() {
	// Parse the command line arguments.
	var cnt = "-1"
	flag.StringVar(&cnt, "c", "0", "initial count")
	flag.StringVar(&inputFileName, "if", "", "input file name")
	flag.StringVar(&outputFileName, "of", "", "output file name")
	flag.StringVar(&proFormaFileName, "pf", "", "proForma file name")
	flag.BoolVar(&encode, "e", false, "encrypt data")
	flag.BoolVar(&decode, "d", false, "decrypt data")
	flag.BoolVar(&useASCII85, "a", false, "use ascii85 encoding")
	flag.BoolVar(&useBinary, "b", false, "use binary output (no encoding)")
	flag.BoolVar(&noCompression, "nc", false, "do not compress input file")
	flag.Parse()

	if (encode && decode) || !(encode || decode) {
		fmt.Fprintln(os.Stderr, "You must select one of -e (encode) or -e (decode)")
		fmt.Fprintln(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(1)
	}
	// Obtain the passphrase used to encrypt the file from either:
	// 1. User input from the terminal
	// 2. The 'tnt2Secret' environment variable
	// 3. Arguments from the entered command line
	var secret string
	var exists bool
	if flag.NArg() == 0 {
		secret, exists = os.LookupEnv("tnt2Secret")
		if !exists {
			if terminal.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "Enter the passphrase: ")
				byteSecret, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				checkFatal(err)
				fmt.Fprintln(os.Stderr, "")
				secret = string(byteSecret)
			}
		}
	} else {
		secret = strings.Join(flag.Args(), " ")
	}

	if len(secret) == 0 {
		fmt.Fprintln(os.Stderr, "You must supply a password.")
		os.Exit(1)
	}

	iCnt, good := new(big.Int).SetString(cnt, 10)
	if !good {
		log.Fatalf("Failed converting counter to a big.Int: [%s]\n", cnt)
	}

	tntMachine.Init([]byte(secret), proFormaFileName)
	if encode {
		tntMachine.SetEngineType("E")
	} else {
		tntMachine.SetEngineType("D")
	}
	// Now the the engine type is set, build the cipher machine.
	tntMachine.BuildCipherMachine()
	mKey = tntMachine.CounterKey()
	// Get the counter file name based on the current user.
	u, err := user.Current()
	checkFatal(err)
	cntrFileName = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, tnt2CountFile)
	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encode the file.
	cMap = make(map[string]*big.Int)
	cMap = readCounterFile(cMap)
	if cMap[mKey] == nil {
		cMap[mKey] = iCnt
	} else {
		iCnt = cMap[mKey]
	}
	// Now we can set the index of the ciper machine.
	tntMachine.SetIndex(iCnt)
}

// checkFatal checks for error that are not io.EOF and io.ErrUnexpectedEOF and logs them.
func checkFatal(e error) {
	if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
		log.Fatal(e)
	}
}

/*
	getInputAndOutputFiles will return the input and output files to use while
	encrypting/decrypting data.  If input and/or output files names were given,
	then those files will be opened.  Otherwise stdin and stdout are used.
*/
func getInputAndOutputFiles() (*os.File, *os.File) {
	var fin *os.File
	var err error

	if len(inputFileName) > 0 {
		if inputFileName == "-" {
			fin = os.Stdin
		} else {
			fin, err = os.Open(inputFileName)
			checkFatal(err)
		}
	} else {
		fin = os.Stdin
	}

	var fout *os.File

	if len(outputFileName) > 0 {
		if outputFileName == "-" {
			fout = os.Stdout
		} else {
			fout, err = os.Create(outputFileName)
			checkFatal(err)
		}
	} else {
		fout = os.Stdout
	}

	return fin, fout
}

// toBinaryHelper provides the means to output pure binary encrypted
// data to the output file along with the number of byte encrypted.
// This is necessary because last block of encrypted data must be output
// in order to properly decrypt it, even if the plain text does not fill
// the final block.
func toBinaryHelper(rdr io.Reader) *io.PipeReader {
	rRdr, rWrtr := io.Pipe()
	var cnt int
	var err error
	var tmpFile *os.File
	plainText := make([]byte, 0)
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	tmpFile, err = os.CreateTemp("", "tnt2*")
	checkFatal(err)
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer os.Remove(tmpFile.Name())
		defer rWrtr.Close()
		err = nil

		for err != io.EOF {
			b := make([]byte, 2048, 2048)
			cnt, err = rdr.Read(b)
			// log.Printf("Read %d bytes\n", cnt)
			checkFatal(err)

			if err != io.EOF {
				plainText = append(plainText, b[:cnt]...)
				for len(plainText) >= tntengine.CypherBlockBytes {
					blk := *new(tntengine.CypherBlock)
					blk.Length = tntengine.CypherBlockBytes
					_ = copy(blk.CypherBlock[:], plainText[:blk.Length])
					leftMost <- blk
					blk = <-rightMost
					cnt, err1 := tmpFile.Write(blk.CypherBlock[:])
					checkFatal(err1)
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
			// log.Printf("decrypting %d bytes\n", cnt)
			leftMost <- blk
			blk = <-rightMost
			_, err1 := tmpFile.Write(blk.CypherBlock[:])
			checkFatal(err1)
			bytesWritten += int64(blk.Length)
		}

		headerLine += fmt.Sprintf("%d\n", bytesWritten)
		_, err = tmpFile.Seek(0, 0)
		checkFatal(err)
		rWrtr.Write([]byte(headerLine))
		_, err = io.Copy(rWrtr, tmpFile)
		checkFatal(err)
		// shutdown the decryption machine by processing a CypherBlock with zero
		// value length field.
		var blk tntengine.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	return rRdr
}

/*
 */
func encrypt() {
	encIn, encOut := io.Pipe()
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	fin, fout := getInputAndOutputFiles()
	var blck pem.Block
	if useASCII85 || useBinary {
		headerLine = "+TNT2|"
		if len(inputFileName) > 0 && inputFileName != "-" {
			headerLine += inputFileName
		}
		if useASCII85 {
			headerLine += "|a"
		} else {
			headerLine += "|b"
		}
		headerLine += fmt.Sprintf("|%s|%s|", fmt.Sprintf("%v", noCompression), tntMachine.Index())
		if useASCII85 {
			fout.WriteString(headerLine + "\n")
		}
	} else {
		blck.Headers = make(map[string]string)
		blck.Type = "TNT2 Encoded Message"
		blck.Headers["Counter"] = fmt.Sprintf("%s", tntMachine.Index())
		if len(inputFileName) > 0 && inputFileName != "-" {
			blck.Headers["FileName"] = inputFileName
		}
		blck.Headers["noCompression"] = fmt.Sprintf("%v", noCompression)
	}

	if useBinary {
		if noCompression {
			encIn = toBinaryHelper(fin)
		} else {
			encIn = toBinaryHelper(flate.ToFlate(fin))
		}
	} else {
		// Go routine to read the output from the encIn, encrypt it and
		// sends it to the appropiate filter (ToPem or ToASCII85).
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer encOut.Close()

			var err error
			var cnt int
			var flateIn io.Reader

			if noCompression {
				flateIn = fin
			} else {
				flateIn = flate.ToFlate(fin)
			}

			plainText := make([]byte, 0)

			for err != io.EOF {
				b := make([]byte, 1024, 1024)
				cnt, err = flateIn.Read(b)
				checkFatal(err)
				bytesRemaining += int64(cnt)
				if err != io.EOF {
					plainText = append(plainText, b[:cnt]...)

					for len(plainText) >= tntengine.CypherBlockBytes {
						blk := *new(tntengine.CypherBlock)
						blk.Length = tntengine.CypherBlockBytes
						_ = copy(blk.CypherBlock[:], plainText)
						leftMost <- blk
						blk = <-rightMost
						cnt, err = encOut.Write(blk.Marshall())
						checkFatal(err)
						bytesWritten += int64(cnt)
						pt := make([]byte, 0)
						pt = append(pt, plainText[tntengine.CypherBlockBytes:]...)
						plainText = pt
					}
				} else if len(plainText) > 0 { // encrypt any remaining input.
					var e error
					blk := *new(tntengine.CypherBlock)
					blk.Length = int8(len(plainText))
					_ = copy(blk.CypherBlock[:], plainText[:blk.Length])
					leftMost <- blk
					blk = <-rightMost
					cnt, e = encOut.Write((blk.Marshall()))
					checkFatal(e)
					bytesWritten += int64(cnt)
				}
			}

			// shutdown the encryption machine by processing a CypherBlock with zero
			// value length field.
			var blk tntengine.CypherBlock
			leftMost <- blk
			_ = <-rightMost
		}()
	}
	// Read the marshalled CyperBlock and send it to STDOUT.
	defer fout.Close()
	var err error
	if useBinary {
		_, err = io.Copy(fout, encIn)
	} else if useASCII85 {
		_, err = io.Copy(fout, lines.SplitToLines(ascii85.ToASCII85(encIn)))
	} else {
		_, err = io.Copy(fout, pem.ToPem(encIn, blck))
	}
	checkFatal(err)
	wg.Wait()
}

// fromBinaryHelper provides the neams to inject the pure binary input
// into the pipe stream used by the decrypt() function.  The data can
// be read using the returned PipeReader.
func fromBinaryHelper(rdr io.Reader) *io.PipeReader {
	rRdr, rWrtr := io.Pipe()
	var cnt int
	var err error
	encText := make([]byte, 0)
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer rWrtr.Close()
		err = nil

		for err != io.EOF {
			b := make([]byte, 2048, 2048)
			cnt, err = rdr.Read(b)
			// log.Printf("Read %d bytes\n", cnt)
			checkFatal(err)

			if err != io.EOF {
				encText = append(encText, b[:cnt]...)
				for len(encText) > tntengine.CypherBlockBytes {
					blk := *new(tntengine.CypherBlock)
					blk.Length = tntengine.CypherBlockBytes
					_ = copy(blk.CypherBlock[:], encText[:blk.Length])
					leftMost <- blk
					blk = <-rightMost
					_, err1 := rWrtr.Write(blk.CypherBlock[:])
					checkFatal(err1)
					bytesRemaining -= int64(blk.Length)
					pt := make([]byte, 0)
					pt = append(pt, encText[blk.Length:]...)
					encText = pt
				}
			}
		}

		if len(encText) > 0 {
			blk := *new(tntengine.CypherBlock)
			blk.Length = int8(len(encText))
			cnt = copy(blk.CypherBlock[:], encText[:blk.Length])
			// log.Printf("decrypting %d bytes\n", cnt)
			leftMost <- blk
			blk = <-rightMost
			_, err1 := rWrtr.Write(blk.CypherBlock[:bytesRemaining])
			checkFatal(err1)
		}

		// shutdown the decryption machine by processing a CypherBlock with zero
		// value length field.
		var blk tntengine.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	return rRdr
}

func decrypt() {
	fin, fout := getInputAndOutputFiles()
	defer fout.Close()
	var ofName string
	var bRdr *bufio.Reader
	var pRdr *io.PipeReader
	bRdr = bufio.NewReader(fin)
	b, err := bRdr.Peek(5)
	checkFatal(err)
	if string(b) == "-----" {
		var blck pem.Block
		pRdr, blck = pem.FromPem(bRdr)
		iCnt, _ = new(big.Int).SetString(blck.Headers["Counter"], 10)
		if len(outputFileName) == 0 {
			fname, ok := blck.Headers["FileName"]
			if ok {
				ofName = fname
			}
		}
		noCmpr, ok := blck.Headers["noCompression"]
		if ok {
			noCompression = noCmpr == "true"
		}
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
				ofName = fields[1]
				useASCII85 = fields[2] == "a"
				useBinary = fields[2] == "b"
				noCompression = fields[3] == "true"
				iCnt, _ = new(big.Int).SetString(fields[4], 10)
				_, err = fmt.Sscanf(fields[5], "%d", &bytesRemaining)
				checkFatal(err)
			}
		}
	}

	if len(outputFileName) == 0 {
		if len(ofName) > 0 {
			var err error
			fout, err = os.Create(ofName)
			checkFatal(err)
		}
	}

	tntMachine.SetIndex(iCnt)
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	decRdr, decWrtr := io.Pipe()

	if !useBinary {
		wg.Add(1)

		go func() {
			defer wg.Done()
			defer decWrtr.Close()
			var err error = nil
			var cnt int
			encText := make([]byte, 0)
			var aRdr *io.PipeReader
			if useASCII85 {
				aRdr = ascii85.FromASCII85(lines.CombineLines(bRdr))
			} else {
				aRdr = pRdr
			}

			for err != io.EOF {
				b := make([]byte, 1024, 1024)
				cnt, err = aRdr.Read(b)
				checkFatal(err)
				log.Printf("Read %d bytes\n", cnt)
				if err != io.EOF {
					encText = append(encText, b[:cnt]...)
					for len(encText) >= tntengine.CypherBlockBytes+1 {
						var blk tntengine.CypherBlock
						blk = *blk.Unmarshall(encText[:tntengine.CypherBlockBytes+1])
						leftMost <- blk
						blk = <-rightMost
						_, e := decWrtr.Write(blk.CypherBlock[:blk.Length])
						checkFatal(e)
						pt := make([]byte, 0)
						pt = append(pt, encText[tntengine.CypherBlockBytes+1:]...)
						encText = pt
					}
				}
			}

			// shutdown the decryption machine by processing a CypherBlock with zero
			// value length field.
			var blk tntengine.CypherBlock
			leftMost <- blk
			_ = <-rightMost
		}()
	}

	var flateRdr *io.PipeReader
	if noCompression {
		if useBinary {
			flateRdr = fromBinaryHelper(bRdr)
		} else {
			flateRdr = decRdr
		}
	} else {
		if useBinary {
			flateRdr = flate.FromFlate(fromBinaryHelper(bRdr))
		} else {
			flateRdr = flate.FromFlate(decRdr)
		}
	}

	_, err = io.Copy(fout, flateRdr)
	checkFatal(err)
	wg.Wait() // Wait for the decryption machine to finish it's clean up.
}

func readCounterFile(defaultMap map[string]*big.Int) map[string]*big.Int {
	f, err := os.OpenFile(cntrFileName, os.O_RDONLY, 0600)
	if err != nil {
		return defaultMap
	}

	defer f.Close()
	cmap := make(map[string]*big.Int)
	dec := gob.NewDecoder(f)
	checkFatal(dec.Decode(&cmap))
	return cmap
}

func writeCounterFile(wMap map[string]*big.Int) error {
	f, err := os.OpenFile(cntrFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer f.Close()
	enc := gob.NewEncoder(f)
	return enc.Encode(wMap)
}

func main() {
	if encode {
		encrypt()
		cMap[mKey] = tntMachine.Index()
		checkFatal(writeCounterFile(cMap))
	} else if decode {
		decrypt()
	}
}

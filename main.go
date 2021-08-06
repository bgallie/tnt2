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
	encode           bool // Flag: True to encode, False to decode.
	decode           bool // Flag: True to decode, False to encode.
	useASCII85       bool // Flag: True to use ascii85 encoding.
	useBinary        bool // Flag: True to output pure binary (no encoding).
	usePem           bool // Flag: True to use PEM encoding.
	compression      bool // Flag: True to compress the file.
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
	flag.StringVar(&cnt, "n", "0", "initial count")
	flag.StringVar(&inputFileName, "if", "", "input file name")
	flag.StringVar(&outputFileName, "of", "", "output file name")
	flag.StringVar(&proFormaFileName, "pf", "", "proForma file name")
	flag.BoolVar(&encode, "e", false, "encrypt data")
	flag.BoolVar(&decode, "d", false, "decrypt data")
	flag.BoolVar(&useASCII85, "a", false, "use ascii85 encoding")
	flag.BoolVar(&usePem, "p", false, "use PEM encoding.")
	flag.BoolVar(&compression, "c", false, "compress input file")
	flag.Parse()

	if (encode && decode) || !(encode || decode) {
		fmt.Fprintln(os.Stderr, "You must select one of -e (encode) or -e (decode)")
		fmt.Fprintln(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// useBinary is the default is useASCII85 or usePem are not selected.
	useBinary = !(useASCII85 || usePem)

	// Obtain the passphrase used to encrypt the file from either:
	// 1. User input from the terminal (most secure)
	// 2. The 'tnt2Secret' environment variable (less secure)
	// 3. Arguments from the entered command line (least secure - not recommended)
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

	tntMachine.Init([]byte(secret), proFormaFileName)
	if encode {
		tntMachine.SetEngineType("E")
	} else {
		tntMachine.SetEngineType("D")
	}

	// Get the starting block count.  cnt can be a number or a fraction such
	// as "1/2", "2/3", or "3/4".  If it is a fraction, then the starting block
	// count is calculated by multiplying the maximal states of the tntEngine
	// by the fraction.
	var good bool
	flds := strings.Split(cnt, "/")
	if len(flds) == 1 {
		iCnt, good = new(big.Int).SetString(cnt, 10)
		if !good {
			log.Fatalf("Failed converting the count to a big.Int: [%s]\n", cnt)
		}
	} else if len(flds) == 2 {
		m := new(big.Int).Set(tntMachine.MaximalStates())
		a, good := new(big.Int).SetString(flds[0], 10)
		if !good {
			log.Fatalf("Failed converting the numerator to a big.Int: [%s]\n", flds[0])
		}
		b, good := new(big.Int).SetString(flds[1], 10)
		if !good {
			log.Fatalf("Failed converting the denominator to a big.Int: [%s]\n", flds[1])
		}
		iCnt = m.Div(m.Mul(m, a), b)
	} else {
		log.Fatalf("Incorrect initial count: [%s]\n", cnt)
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
	} else if inputFileName == "-" {
		fout = os.Stdout
	} else {
		outputFileName = inputFileName + ".tnt2"
		fout, err = os.Create(outputFileName)
		checkFatal(err)
	}

	return fin, fout
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
			leftMost <- blk
			blk = <-rightMost
			_, err1 := tmpFile.Write(blk.CypherBlock[:])
			checkFatal(err1)
			bytesWritten += int64(blk.Length)
		}

		_, err = tmpFile.Seek(0, 0)
		checkFatal(err)
		rWrtr.Write([]byte(fmt.Sprintf("%d\n", bytesWritten)))
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
	var encIn *io.PipeReader
	// leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	fin, fout := getInputAndOutputFiles()
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
	var err error
	bRdr := bufio.NewReader(encIn)
	if useBinary {
		_, err = io.Copy(fout, bRdr)
	} else if useASCII85 {
		line, err := bRdr.ReadString('\n')
		checkFatal(err)
		_, err = fout.Write([]byte(line))
		checkFatal(err)
		_, err = io.Copy(fout, lines.SplitToLines(ascii85.ToASCII85(encIn)))
	} else {
		line, err := bRdr.ReadString('\n')
		checkFatal(err)
		blck.Headers["FileSize"] = line[:len(line)-1]
		_, err = io.Copy(fout, pem.ToPem(bRdr, blck))
	}
	checkFatal(err)
	wg.Wait()
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
		checkFatal(err)
	}()
	return rRdr
}

func decrypt() {
	fin, fout := getInputAndOutputFiles()
	defer fout.Close()
	var ofName string
	var bRdr *bufio.Reader
	var pRdr *io.PipeReader
	var err error
	bRdr = bufio.NewReader(fin)
	b, err := bRdr.Peek(5)
	checkFatal(err)
	if string(b) == "-----" {
		usePem = true
		var blck pem.Block
		pRdr, blck = pem.FromPem(bRdr)
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
				ofName = fields[1]
				useASCII85 = fields[2] == "a"
				useBinary = fields[2] == "b"
				compression = fields[3] == "true"
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
			b := make([]byte, 1024, 1024)
			cnt, err = aRdr.Read(b)
			checkFatal(err)
			if err != io.EOF {
				encText = append(encText, b[:cnt]...)
				for len(encText) >= tntengine.CypherBlockBytes {
					blk := *new(tntengine.CypherBlock)
					blk.Length = tntengine.CypherBlockBytes
					_ = copy(blk.CypherBlock[:], encText[:blk.Length])
					leftMost <- blk
					blk = <-rightMost
					var err1 error
					if bytesRemaining < int64(blk.Length) {
						_, err1 = decWrtr.Write(blk.CypherBlock[:bytesRemaining])
					} else {
						_, err1 = decWrtr.Write(blk.CypherBlock[:])
					}
					checkFatal(err1)
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

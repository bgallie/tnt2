// tnt2 project main.go
// tnt2 is an implementation of the "Infinite Key Ecryption" system from the
// Dr. Dobbs Journal artical.

package main

import (
	"bufio"
	"encoding/ascii85"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/bits"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/bgallie/filters"
	"github.com/bgallie/jc1"
	"github.com/bgallie/tnt2/cryptors"
	"github.com/bgallie/utilities"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	tnt2CountFile = ".tnt2"
	usage         = "tnt2 [[-decode | -d] | [-encode | -e]] <inputfile >outputfile"
)

var (
	encode           bool              // Flag: True to encode, False to decode
	decode           bool              // Flag: True to decode, False to encode
	useASCII85       bool              // Flag: True to using ascii85 encoding, False to use PEM encoding
	counter          *cryptors.Counter = new(cryptors.Counter)
	proFormaMachine  []cryptors.Crypter
	tntMachine       []cryptors.Crypter
	rotorSizes       []int
	rotorSizesIndex  int
	cycleSizes       []int
	cycleSizesIndex  int
	key              *jc1.UberJc1
	mKey             string
	iCnt             *big.Int
	logIt            bool
	cMap             map[string]*big.Int
	cntrFileName     string
	inputFileName    string
	outputFileName   string
	logFileName      string
	proFormaFileName string
	proFormaFile     os.File
	perm             func(int) []byte
	intn             func(int) int
	inputFile        = os.Stdin
	outputFile       = os.Stdout
	checkFatal       = utilities.CheckFatal
	turnOffLogging   = utilities.TurnOffLogging
	turnOnLogging    = utilities.TurnOnLogging
	setLogFileName   = utilities.SetLogFileName
)

func init() {
	// Parse the command line arguments.
	var cnt = "-1"
	flag.StringVar(&cnt, "count", "0", "initial count")
	flag.StringVar(&cnt, "c", "0", "initial count (shorthand)")
	flag.StringVar(&inputFileName, "inputFile", "", "input file name")
	flag.StringVar(&inputFileName, "if", "", "input file name (shorthand)")
	flag.StringVar(&outputFileName, "outputFile", "", "output file name")
	flag.StringVar(&outputFileName, "of", "", "output file name (shorthand)")
	flag.StringVar(&logFileName, "logFile", "", "log file name [implies -log]")
	flag.StringVar(&logFileName, "lf", "", "log file name (shorthand) [implies -l]")
	flag.StringVar(&proFormaFileName, "proformaFile", "", "proForma file name")
	flag.StringVar(&proFormaFileName, "pf", "", "proForma file name (shorthand)")
	flag.BoolVar(&encode, "encode", false, "encrypt data")
	flag.BoolVar(&encode, "e", false, "encrypt data (shorthand)")
	flag.BoolVar(&decode, "decode", false, "decrypt data")
	flag.BoolVar(&decode, "d", false, "decrypt data (shorthand)")
	flag.BoolVar(&logIt, "log", false, "turn logging on")
	flag.BoolVar(&logIt, "l", false, "turn logging on (shorthand)")
	flag.BoolVar(&useASCII85, "a", false, "use ascii85 encodeing (shorthand)")
	flag.BoolVar(&useASCII85, "ascii85", false, "use ascii85 encoding")
	flag.Parse()

	if (encode && decode) || !(encode || decode) {
		fmt.Fprintln(os.Stderr, "You must select one of -encode or -decode")
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
	// Initialize the uberJc1 generator with the passphrase.
	key = jc1.NewUberJc1([]byte(secret))

	if len(logFileName) != 0 {
		setLogFileName(logFileName)
		turnOnLogging() // Set the log file to the named log file.
	}

	if !logIt {
		turnOffLogging()
	}

	// Create an ecryption machine based on the proForma rotors and permutators.
	proFormaMachine = *createProFormaMachine(proFormaFileName)
	leftMost, rightMost := cryptors.CreateEncryptMachine(cryptors.BigZero, proFormaMachine...)
	// Create a random number function [func(max int) int] that uses psudo-
	// random data generated the proforma encryption machine.
	intn = createRandomNumberFunction(leftMost, rightMost)
	// Create a permutaton function that returns bytes in [0, n] in (psudo-)
	// random order
	perm = func(n int) []byte {
		res := make([]byte, n, n)

		for i := range res {
			res[i] = byte(i)
		}

		for i := (n - 1); i > 0; i-- {
			j := intn(i)
			res[i], res[j] = res[j], res[i]
		}

		return res
	}
	// Get the counter file name based on the current user.
	u, err := user.Current()
	checkFatal(err)
	cntrFileName = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, tnt2CountFile)

	// Get a 'checksum' of the encryption key.  This is used as a key to store
	// the block number to use as a starting point for the next encryption.
	var blk cryptors.CypherBlock
	var cksum [cryptors.CypherBlockBytes]byte
	var eCksum [int((cryptors.CypherBlockBytes / 4.0) * 5)]byte
	blk.Length = cryptors.CypherBlockBytes
	_ = copy(blk.CypherBlock[:], key.XORKeyStream(cksum[:]))
	leftMost <- blk
	blk = <-rightMost
	ascii85.Encode(eCksum[:], blk.CypherBlock[:])
	mKey = string(eCksum[:])
	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encode the file.
	cMap = make(map[string]*big.Int)
	cMap = readCounterFile(cMap)

	iCnt, _ = new(big.Int).SetString(cnt, 10)
	if cMap[mKey] == nil {
		cMap[mKey] = iCnt
	} else {
		iCnt = cMap[mKey]
	}

	// Shuffle the order of rotor sizes based on the key.
	for k := len(cryptors.RotorSizes) - 1; k > 2; k-- {
		l := intn(k)
		cryptors.RotorSizes[k], cryptors.RotorSizes[l] =
			cryptors.RotorSizes[l], cryptors.RotorSizes[k]
	}
	cryptors.RotorSizes[2], cryptors.RotorSizes[1] =
		cryptors.RotorSizes[1], cryptors.RotorSizes[2]

	// Define a random order of cycle sizes based on the key.
	for k := len(cryptors.CycleSizes) - 1; k > 2; k-- {
		l := intn(k)
		cryptors.CycleSizes[k], cryptors.CycleSizes[l] =
			cryptors.CycleSizes[l], cryptors.CycleSizes[k]
	}
	cryptors.CycleSizes[2], cryptors.CycleSizes[1] =
		cryptors.CycleSizes[1], cryptors.CycleSizes[2]

	// Update the rotors and permutators in a very non-linear fashion.
	for pfCnt, machine := range proFormaMachine {
		switch v := machine.(type) {
		default:
			fmt.Fprintf(os.Stderr, "Unknown machine: %v\n", v)
		case *cryptors.Rotor:
			updateRotor(machine.(*cryptors.Rotor), leftMost, rightMost)
		case *cryptors.Permutator:
			p := new(cryptors.Permutator)
			updatePermutator(p, leftMost, rightMost)
			proFormaMachine[pfCnt] = p
		case *cryptors.Counter:
			machine.(*cryptors.Counter).SetIndex(cryptors.BigZero)
		}
	}

	// Update the tntMachine to change the order of rotors and permutators in a randon order.
	tntMachine = make([]cryptors.Crypter, 9, 9)
	// Scramble the order of the rotors and permutators
	tntOrder := perm(len(tntMachine) - 1)
	for i, v := range tntOrder {
		tntMachine[i] = proFormaMachine[v]
	}
	// Add the special 'counter' encryptor to count the number of blocks encrypted
	tntMachine[len(tntMachine)-1] = counter
}

/*
	createRandomNumberFunction returns a function [func(max int) int] that will
	return a uniform random value in [0, max) using psudo-random bytes generated
	by the TNT2 encryption algorithm. It panics if max <= 0.

	'left' is the input channel and 'right' is the output channel for the TNT2
	encryption machine.
*/
func createRandomNumberFunction(left chan cryptors.CypherBlock, right chan cryptors.CypherBlock) func(int) int {
	/*
		'blk' contains the data that is encrypted and is initializd to data
		generated from the uberJc1 algorithm based on the secret key enterd
		by the user.
	*/
	var blk cryptors.CypherBlock
	blk.Length = cryptors.CypherBlockBytes
	blkSlice := blk.CypherBlock[:]
	go copy(blkSlice, key.XORKeyStream(blkSlice))

	return func(max int) int {
		for {
			if max <= 0 {
				panic("argument to intn is <= 0")
			}

			n := max - 1
			// bitLen is the maximum bit length needed to encode a value < max.
			bitLen := bits.Len(uint(n))
			if bitLen == 0 {
				// the only valid result is 0
				return n
			}
			// k is the maximum byte length needed to encode a value < max.
			k := (bitLen + 7) / 8
			// b is the number of bits in the most significant byte of max-1.
			b := uint(bitLen % 8)
			if b == 0 {
				b = 8
			}

			bytes := make([]byte, k)

			for {
				// If there are not enough bytes in 'blk' to get 'k' bytes, get
				// the next 32 psudo-random bytes into 'blk'
				if blk.Length+int8(k) > 31 {
					blk.Length = cryptors.CypherBlockBytes
					left <- blk
					blk = <-right
					blk.Length = 0
				}
				// Get the next 'k' psudo-random bytes generated by the TNT2
				// encryption machine.
				copy(bytes[0:], blk.CypherBlock[blk.Length:blk.Length+int8(k)])
				blk.Length += int8(k)

				// Clear bits in the first byte to increase the probability
				// that the candidate is < max.
				bytes[0] &= uint8(int(1<<b) - 1)

				// Change the data in the byte slice into an integer ('n')
				n = 0
				for _, val := range bytes {
					n = (n << 8) | int(val)
				}

				if n < max {
					return n
				}
			}
		}
	}
}

/*
	createProFormaMachine initializes the pro-forma machine used to create the
	TNT2 encryption machine.  If the machineFileName is not empty then the
	pro-forma machine is loaded from that file, else the hardcoded rotors and
	permutators are used to initialize the pro-formaa machine.
*/
func createProFormaMachine(machineFileName string) *[]cryptors.Crypter {
	var newMachine []cryptors.Crypter
	if len(machineFileName) == 0 {
		log.Println("Using built in proforma rotors and permutators")

		// Create the proforma encryption machine.  The layout of the machine is:
		// 		rotor, rotor, permutator, rotor, rotor, permutator, rotor, rotor
		newMachine = []cryptors.Crypter{cryptors.Rotor1, cryptors.Rotor2, cryptors.Permutator1,
			cryptors.Rotor3, cryptors.Rotor4, cryptors.Permutator2,
			cryptors.Rotor5, cryptors.Rotor6}
	} else {
		log.Printf("Using proforma rotors and permutators from %s\n", machineFileName)
		in, err := os.Open(machineFileName)
		checkFatal(err)
		jDecoder := json.NewDecoder(in)
		// Create the proforma encryption machine from the given proforma machine file.
		// The layout of the machine is:
		// 		rotor, rotor, permutator, rotor, rotor, permutator, rotor, rotor
		var rotor1, rotor2, rotor3, rotor4, rotor5, rotor6 *cryptors.Rotor
		var permutator1, permutator2 *cryptors.Permutator
		newMachine = []cryptors.Crypter{rotor1, rotor2, permutator1, rotor3, rotor4, permutator2, rotor5, rotor6}

		for cnt, machine := range newMachine {
			switch v := machine.(type) {
			default:
				fmt.Fprintf(os.Stderr, "Unknown machine: %v\n", v)
			case *cryptors.Rotor:
				r := new(cryptors.Rotor)
				err = jDecoder.Decode(&r)
				checkFatal(err)
				newMachine[cnt] = r
			case *cryptors.Permutator:
				p := new(cryptors.Permutator)
				err = jDecoder.Decode(&p)
				checkFatal(err)
				newMachine[cnt] = p
			}
		}
	}

	return &newMachine
}

/*
	updateRotor will update the given (proforma) rotor in place using (psudo-
	random) data generated by the TNT2 encrytption algorithm using the pro-forma
	rotors and permutators.
*/
func updateRotor(r *cryptors.Rotor, left, right chan cryptors.CypherBlock) {
	// Get size, start and step of the new rotor
	rotorSize := cryptors.RotorSizes[rotorSizesIndex]
	rotorSizesIndex = (rotorSizesIndex + 1) % len(cryptors.RotorSizes)
	start := intn(rotorSize)
	step := intn(rotorSize)

	// blkCnt is the total number of bytes needed to hold rotorSize bits + a slice of 256 bits
	blkCnt := (((rotorSize + cryptors.CypherBlockSize + 7) / 8) + 31) / 32
	// blkBytes is the number of bytes rotor r needs to increase to hold the new rotor.
	blkBytes := (blkCnt * 32) - len(r.Rotor)
	// Adjust the size of r.Rotor to match the new rotor size.
	adjRotor := make([]byte, blkBytes)
	r.Rotor = append(r.Rotor, adjRotor...)
	var blk cryptors.CypherBlock
	blk.Length = cryptors.CypherBlockBytes
	blkSlice := blk.CypherBlock[:]
	// Fill the rotor with random data using TNT2 encryption to generate the
	// random data by encrypting the next 32 bytes of data from the uberJC1
	// algorithm until the next rotor is filled.
	for i := 0; i < blkCnt; i++ {
		copy(blkSlice, key.XORKeyStream(blkSlice))
		left <- blk
		blk = <-right
		copy(r.Rotor[i*cryptors.CypherBlockBytes:], blk.CypherBlock[:])
	}

	// update the rotor with the new size, start, and step and slice the first
	// 256 bits of the rotor to the end of the rotor.
	r.Update(rotorSize, start, step)
}

/*
	updatePermutator will update the given (proforma) permutator in place using
	(psudo-random) data generated by the TNT2 encrytption algorithm using the
	proforma rotors and permutators.
*/
func updatePermutator(p *cryptors.Permutator, left, right chan cryptors.CypherBlock) {
	var randp [cryptors.CypherBlockSize]byte
	// Create a table of byte values [0...255] in a random order
	for i, val := range perm(cryptors.CypherBlockSize) {
		randp[i] = val
	}
	// Chose a cryptors.CycleSizes and randomize order of the values
	length := len(cryptors.CycleSizes[cycleSizesIndex])
	cycles := make([]int, length, length)
	randi := perm(length)
	for idx, val := range randi {
		cycles[idx] = cryptors.CycleSizes[cycleSizesIndex][val]
	}
	p.Update(cycles, randp[:])
	cycleSizesIndex = (cycleSizesIndex + 1) % len(cryptors.CycleSizes)
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

/*
 */
func encrypt() {
	encIn, encOut := io.Pipe()
	leftMost, rightMost := cryptors.CreateEncryptMachine(iCnt, tntMachine...)
	fin, fout := getInputAndOutputFiles()
	var blck filters.Block
	if useASCII85 {
		fout.WriteString(fmt.Sprintf("%s\n", iCnt))
	} else {
		blck.Headers = make(map[string]string)
		blck.Type = "TNT2 Encoded Message"
		blck.Headers["Counter"] = fmt.Sprintf("%s", iCnt)
		if len(inputFileName) > 0 && inputFileName != "-" {
			blck.Headers["FileName"] = inputFileName
		}
	}

	// Go routine to read the output from the encIn, encrypt it and
	// sends it to the appropiate filter (ToPem or ToASCII85).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer encOut.Close()
		flateIn := filters.ToFlate(fin)
		var err error
		var cnt int
		plainText := make([]byte, 0)

		for err != io.EOF {
			var blk cryptors.CypherBlock
			b := make([]byte, 1024, 1024)
			cnt, err = flateIn.Read(b)
			checkFatal(err)

			if err != io.EOF {
				plainText = append(plainText, b[:cnt]...)

				for len(plainText) >= cryptors.CypherBlockBytes {
					_ = copy(blk.CypherBlock[:], plainText)
					blk.Length = cryptors.CypherBlockBytes
					leftMost <- blk
					blk = <-rightMost
					log.Println(blk.String())
					cnt, err = encOut.Write(blk.Marshall())
					checkFatal(err)
					pt := make([]byte, 0)
					pt = append(pt, plainText[cryptors.CypherBlockBytes:]...)
					plainText = pt
				}
			} else if len(plainText) > 0 { // encrypt any remaining input.
				var e error
				blk.Length = int8(len(plainText))
				_ = copy(blk.CypherBlock[:], plainText[:blk.Length])
				blk.Length = int8(len(plainText))
				leftMost <- blk
				log.Println(blk.String())
				blk = <-rightMost
				cnt, e = encOut.Write((blk.Marshall()))
				checkFatal(e)
			}
		}

		// shutdown the encryption machine by processing a CypherBlock with zero
		// value length field.
		var blk cryptors.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	// Read the marshalled CyperBlock and send it to STDOUT.
	defer fout.Close()
	var err error
	if useASCII85 {
		_, err = io.Copy(fout, filters.SplitToLines(filters.ToASCII85(encIn)))
	} else {
		_, err = io.Copy(fout, filters.ToPem(encIn, blck))
	}
	checkFatal(err)
	wg.Wait()
}

func decrypt() {
	fin, fout := getInputAndOutputFiles()
	defer fout.Close()
	var bRdr *bufio.Reader
	var pRdr *io.PipeReader
	if useASCII85 {
		bRdr = bufio.NewReader(fin)
		line, err := bRdr.ReadString('\n')

		if err == nil {
			iCnt, _ = new(big.Int).SetString(line[:len(line)-1], 10)
		}
	} else {
		var blck filters.Block
		pRdr, blck = filters.FromPem(fin)
		iCnt, _ = new(big.Int).SetString(blck.Headers["Counter"], 10)
		if len(outputFileName) == 0 {
			fname, ok := blck.Headers["FileName"]
			if ok {
				var err error
				fout, err = os.Create(fname)
				checkFatal(err)
			}
		}
	}

	leftMost, rightMost := cryptors.CreateDecryptMachine(iCnt, tntMachine...)
	decRdr, decWrtr := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer decWrtr.Close()
		var err error = nil
		var cnt int
		encText := make([]byte, 0)
		var aRdr *io.PipeReader
		if useASCII85 {
			aRdr = filters.FromASCII85(filters.CombineLines(bRdr))
		} else {
			aRdr = pRdr
		}

		for err != io.EOF {
			b := make([]byte, 1024, 1024)
			cnt, err = aRdr.Read(b)
			checkFatal(err)

			if err != io.EOF {
				encText = append(encText, b[:cnt]...)

				for len(encText) >= cryptors.CypherBlockBytes+1 {
					var blk cryptors.CypherBlock
					blk = *blk.Unmarshall(encText[:cryptors.CypherBlockBytes+1])
					leftMost <- blk
					blk = <-rightMost
					log.Println(blk.String())
					_, e := decWrtr.Write(blk.CypherBlock[:blk.Length])
					checkFatal(e)
					pt := make([]byte, 0)
					pt = append(pt, encText[cryptors.CypherBlockBytes+1:]...)
					encText = pt
				}
			}
		}

		// shutdown the decryption machine by processing a CypherBlock with zero
		// value length field.
		var blk cryptors.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	_, err := io.Copy(fout, filters.FromFlate(decRdr))
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
	dec := json.NewDecoder(f)
	checkFatal(dec.Decode(&cmap))
	return cmap
}

func writeCounterFile(wMap map[string]*big.Int) error {
	f, err := os.OpenFile(cntrFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return err
	}

	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "    ")
	return e.Encode(wMap)
}

func main() {
	if encode {
		encrypt()
		cMap[mKey] = tntMachine[len(tntMachine)-1].Index()
		checkFatal(writeCounterFile(cMap))
	} else if decode {
		decrypt()
	}
}

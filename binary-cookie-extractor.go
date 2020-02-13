/*
  Title: binary-cookie-extractor

  Description: This go program is used to extract the cookies located in Safari/iOS/iPadOS cookie caches,
  the Cookie.binarycookies file. Simply provide the path to a valid Cookie.binarycookies file and this
  program will decode them and print them out.

  Usage:
  $ ./binary-cookie-extractor -i <PATH-TO-COOKIE-FILE> [-v] [-d] [-f table|list]

  Examples:
  $ ./binary-cookie-extractor -i Cookie.binarycookies
  $ ./binary-cookie-extractor -i Cookie.binarycookies -f list

  Created by @KittyNighthawk (2020) (https://github.com/KittyNighthawk)
*/

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"time"
)

type pages struct {
	pages      []page
	numPages   uint64
	pageSizes  []uint64
	headerSize uint64
}

type page struct {
	rawBytes         []byte
	numCookiesInPage uint64
	cookieOffsets    []uint64
	cookies          []cookie
}

type cookie struct {
	rawBytes     []byte
	size         uint64
	name         string
	value        string
	domain       string
	path         string
	flags        string
	expires      time.Time
	lastAccessed time.Time
}

// Command line flag variables
var file = flag.String("i", "", "path to the binary cookies file")
var version = flag.Bool("v", false, "display version number")
var debug = flag.Bool("d", false, "display debugging information")
var format = flag.String("f", "table", "format of output [table|list]")

func main() {
	parseComLineFlags()

	data, err := ioutil.ReadFile(*file)
	handleError(err)

	checkFileMagicNumber(data)

	// The data is provided to extractPages which returns a new pages object populated with the pages
	pages := extractPages(data)

	// Next, the pages reference is passed to extractCookiesFromPages, which extracts the cookies from the pages page objects
	// extractCookiesFromPages modifies the objects the reference passes to, so it doesn't need to return anything
	extractCookiesFromPages(pages)

	// At this point, the pages have been extracted, and the cookies extracted from the pages, so last step is to just
	// decode the cookies in each page
	decodeCookies(pages)

	// Now print out the cookies!
	printDecodedCookies(pages)
}

// This function prints out decoded cookies
func printDecodedCookies(pages pages) {
	// First, loop through the pages
	cookieCount := 1
	for i := 0; i < len(pages.pages); i++ {
		// And now loop through the cookies in those pages
		for j := 0; j < len(pages.pages[i].cookies); j++ {
			switch *format {
			case "table":
				fmt.Printf("Cookie %d: %s=", cookieCount, pages.pages[i].cookies[j].name)
				fmt.Printf("%s; ", pages.pages[i].cookies[j].value)
				fmt.Printf("Domain: %s; ", pages.pages[i].cookies[j].domain)
				fmt.Printf("Path: %s; ", pages.pages[i].cookies[j].path)
				fmt.Printf("Expires: %v; ", pages.pages[i].cookies[j].expires)
				fmt.Printf("Last Accessed: %v; ", pages.pages[i].cookies[j].lastAccessed)
				fmt.Printf("%s\n", pages.pages[i].cookies[j].flags)
				cookieCount += 1
			case "list":
				fmt.Printf("Name: %s\n", pages.pages[i].cookies[j].name)
				fmt.Printf("Value: %s\n", pages.pages[i].cookies[j].value)
				fmt.Printf("Domain: %s\n", pages.pages[i].cookies[j].domain)
				fmt.Printf("Path: %s\n", pages.pages[i].cookies[j].path)
				fmt.Printf("Expires: %v\n", pages.pages[i].cookies[j].expires)
				fmt.Printf("Last Accessed: %v\n", pages.pages[i].cookies[j].lastAccessed)
				fmt.Printf("Flags: %s\n\n", pages.pages[i].cookies[j].flags)
			default:
				fmt.Printf("This should never run\n")
			}
		}
	}
}

// This function takes a pages object and will decode the cookies within the individual pages. Nothing is returned as it
// modifies the objects the pages reference points to
func decodeCookies(pages pages) {
	// First, loop through the pages
	for i := 0; i < len(pages.pages); i++ {
		// Now, loop through the cookies within each page
		for j := 0; j < len(pages.pages[i].cookies); j++ {
			// And here you can access each cookie object individually, so decode them and update each cookies instance variables
			// Decode size of individual cookies
			a := pages.pages[i].cookies[j].rawBytes[:4]
			intA := int(convertHexToUint(reverseByteSlice(a)))
			pages.pages[i].cookies[j].size = uint64(intA)

			// Decode the flags of individual cookies
			// Cookie flag decodings
			// 0x0 - no cookie flags
			// 0x1 - secure flag only
			// 0x4 - httponly flag only
			// 0x5 - secure + httponly flags set
			b := int(convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[8:12])))
			var flagText string
			switch b {
			case 0:
				flagText = "None"
			case 1:
				flagText = "Secure"
			case 4:
				flagText = "HttpOnly"
			case 5:
				flagText = "Secure; HttpOnly"
			default:
				flagText = "Unknown"
			}
			pages.pages[i].cookies[j].flags = flagText

			// Determine offsets for the other values (needed to know where to carve values from)
			domainOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[16:20])) // 4 byte field
			nameOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[20:24]))   // 4 byte field
			pathOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[24:28]))   // 4 byte field
			valueOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[28:32]))  // 4 byte field

			// Carve the values from the raw cookie bytes using the above offsets, and set the cookie instance variables to the carved values
			// Each value is null terminated and variable in length, so scanUntilNullByte grabs everything from the offset until it sees 0x00
			pages.pages[i].cookies[j].name = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[nameOffset:]))
			pages.pages[i].cookies[j].value = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[valueOffset:]))
			pages.pages[i].cookies[j].domain = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[domainOffset:]))
			pages.pages[i].cookies[j].path = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[pathOffset:]))

			// Now for the timestamps. These are big-endian double precision (or float64 in Go) values of Cocoa Core Data epochs
			expiresRaw := pages.pages[i].cookies[j].rawBytes[40:48]      // 8 byte field
			lastAccessedRaw := pages.pages[i].cookies[j].rawBytes[48:56] // 8 byte field
			pages.pages[i].cookies[j].expires = convertHexToCoreDataTime(expiresRaw)
			pages.pages[i].cookies[j].lastAccessed = convertHexToCoreDataTime(lastAccessedRaw)
		}
	}
}

// This function pages a pages object and extracts the cookies from each page within the pages object into cookie objects.
// No cookie decoding is done here, this just gets the raw cookie bytes out for later decoding
func extractCookiesFromPages(pages pages) {
	// Loop through each page
	for i := 0; i < len(pages.pages); i++ {
		// First, get the number of cookies in the current page
		a, _ := strconv.ParseUint(hex.EncodeToString(reverseByteSlice(pages.pages[i].rawBytes[4:8])), 10, 64)
		pages.pages[i].numCookiesInPage = a
		if *debug {
			fmt.Printf("[DEBUG] Number of cookies in page (%d): %d\n", i+1, pages.pages[i].numCookiesInPage)
		}

		// Next, get the offsets for the cookies (loop numCookiesInPage times)
		startOffset, endOffset := 8, 12
		for j := 0; j < int(pages.pages[i].numCookiesInPage); j++ {
			cookieLen := convertHexToUint(reverseByteSlice(pages.pages[i].rawBytes[startOffset:endOffset]))
			pages.pages[i].cookieOffsets = append(pages.pages[i].cookieOffsets, cookieLen)
			startOffset += 4
			endOffset += 4
		}

		// Next, extract the raw cookies (in byte slices) from the current page using the offsets from above
		for k := 0; k < len(pages.pages[i].cookieOffsets); k++ {
			// For last cookie, just go from last offset to end of rawBytes; otherwise, use the offsets
			if k == len(pages.pages[i].cookieOffsets)-1 {
				var newCookie cookie
				if *debug {
					fmt.Printf("[DEBUG] Loop check (Page: %d): k=%v, len()=%v (Value: %v)\n", i, k, len(pages.pages[i].cookieOffsets)-1, pages.pages[i].cookieOffsets)
				}
				newCookie.rawBytes = pages.pages[i].rawBytes[int(pages.pages[i].cookieOffsets[k]):]
				pages.pages[i].cookies = append(pages.pages[i].cookies, newCookie)
			} else {
				var newCookie cookie
				if *debug {
					fmt.Printf("[DEBUG] Loop check (Page: %d): k=%v, len()=%v (Value: %v)\n", i, k, len(pages.pages[i].cookieOffsets)-1, pages.pages[i].cookieOffsets)
				}
				newCookie.rawBytes = pages.pages[i].rawBytes[int(pages.pages[i].cookieOffsets[k]):int(pages.pages[i].cookieOffsets[k+1])]
				pages.pages[i].cookies = append(pages.pages[i].cookies, newCookie)
			}
		}
	}
	// At this point, the pages objects contain page objects, and the page objects contain raw cookies. Next is to decode the cookies
}

// This function takes a byte array (the contents of te file) and populates the pages struct with values from the data
func extractPages(data []byte) pages {
	var pages pages
	pages.numPages = convertHexToUint(data[4:8])
	if *debug {
		fmt.Printf("[DEBUG] Number of pages: %d\n", pages.numPages)
	}
	pages.pageSizes = parseSizeOfPages(data, pages.numPages)
	pages.headerSize = pages.numPages*4 + 8
	if *debug {
		fmt.Printf("[DEBUG] Size of header: %d bytes\n", pages.headerSize)
	}

	var offsetCounter uint64
	// Need to extract each page to a new page object, then store those page objects within pages pages []page variable
	for i := 0; i < len(pages.pageSizes); i++ {
		var page page
		//FIXME! THIS IS THE PROBLEM! The slice subcript is the same for BOTH instances, need to account for offsets!
		// It is ALWAYS starting from the first byte after the header, even for the 2nd, 3rd, nth page!
		if i == len(pages.pageSizes)-1 {
			// You're at the last offset in pageSizes, so just slice to the end of data
			page.rawBytes = data[pages.headerSize+offsetCounter:]
		} else {
			// There's another offset after the current one in pageSizes, so use the offsets to determine where to slice
			page.rawBytes = data[pages.headerSize+offsetCounter : pages.headerSize+pages.pageSizes[i]]
			offsetCounter += pages.pageSizes[i]
		}
		pages.pages = append(pages.pages, page)
		if *debug {
			fmt.Printf("[DEBUG] Value of rawBytes in page %d: %v\n", i+1, page.rawBytes)
		}
	}
	return pages
}

// This function scan a byte slice until it finds the first instance of a null byte (0x00). It then returns a new slice
// from the beginning of data to the byte before the first null byte
func scanUntilNullByte(data []byte) []byte {
	var result []byte
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			break
		} else {
			result = append(result, data[i])
		}
	}
	return result
}

// This function takes a byte slice and reverses the order of bytes (useful for converting between little and big endian)
func reverseByteSlice(data []byte) []byte {
	var result []byte
	for i := len(data) - 1; i >= 0; i-- {
		result = append(result, data[i])
	}
	return result
}

// This function takes the file data and the number of pages. It returns a uint64 array containing the size (in decimal) of each page
func parseSizeOfPages(data []byte, pages uint64) []uint64 {
	startOffset, endOffset := 8, 12
	var result []uint64

	for i := 0; i < int(pages); i++ {
		pageSize := convertHexToUint(data[startOffset:endOffset])
		startOffset += 4
		endOffset += 4
		result = append(result, pageSize)
		if *debug {
			fmt.Printf("[DEBUG] Size of page %d: %d bytes\n", i+1, pageSize)
		}
	}
	return result
}

// This function converts a byte slice (like [00 00 02 2b]) to its Uint64 equivalent (like 555)
func convertHexToUint(bytes []byte) uint64 {
	a := hex.EncodeToString(bytes)
	b, _ := strconv.ParseUint(a, 16, 64)
	return b
}

// This function takes a hexadecimal byte slice containing a Cocoa Core Data epoch time and returns a string of the human-readable
// time
func convertHexToCoreDataTime(bytes []byte) time.Time {
	a := hex.EncodeToString(reverseByteSlice(bytes))
	b, _ := strconv.ParseUint(a, 16, 64)
	c := math.Float64frombits(b)
	d := int64(c)
	// Different between UNIX and Core Data epoch is: UNIX - 978307200 = Core Data
	e := time.Unix(d+978307200, 0)
	return e
}

func parseComLineFlags() {
	flag.Parse()

	if *version {
		fmt.Println("BinaryCookieExtractor (v0.9) - @KittyNighthawk (2020)")
		os.Exit(1)
	}

	if *file == "" {
		fmt.Println("No parameters supplied!\n")
		printUsageInstructions()
		os.Exit(1)
	}

	if *format != "table" && *format != "list" {
		if *debug {
			fmt.Printf("[DEBUG] *format does not equal table, list, or json\n")
			fmt.Printf("[DEBUG] *format: %s\n", *format)
		}
		printUsageInstructions()
		os.Exit(1)
	}
}

func printUsageInstructions() {
	fmt.Println(`BinaryCookieExtractor (v0.9) - Safari/iOS/iPadOS Binary Cookie Decoder - @KittyNighthawk (2020)

Usage: $ ./binary-cookie-extractor -i <BINARY-COOKIE-FILE> [-f table|list|json] [-d]
Example: $ ./binary-cookie-extractor -i Cookies.binarycookies

For help, enter: $ ./binary-cookie-decode -h`)
}

func handleError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "An error occured: %v\n", err)
		os.Exit(1)
	}
}

// This function checks that the file provided matches the binary cookies magic number
func checkFileMagicNumber(data []byte) {
	magicNum := data[:4]
	if string(magicNum) != "cook" {
		fmt.Fprintf(os.Stderr, "File is not a valid iOS/Safari binary cookies file... exiting\n")
		os.Exit(1)
	}
}

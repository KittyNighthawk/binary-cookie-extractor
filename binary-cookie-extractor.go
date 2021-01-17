/*
  Title: binary-cookie-extractor

  Description: This go program is used to extract the cookies located in Safari/iOS/iPadOS cookie caches,
  the Cookie.binarycookies file. Simply provide the path to a valid Cookie.binarycookies file and this
  program will decode them and print them out.

  Usage:
  $ ./binary-cookie-extractor -i <BINARY-COOKIE-FILE> [-f table|list|json|csv|xml] [-d]

  Examples:
  $ ./binary-cookie-extractor -i Cookie.binarycookies
  $ ./binary-cookie-extractor -i Cookie.binarycookies -f list
  $ ./binary-cookie-extractor -i Cookie.binarycookies -f json
  $ ./binary-cookie-extractor -i Cookie.binarycookies -f xml

  Created by @KittyNighthawk (2021) (https://github.com/KittyNighthawk)
*/

package main

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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
	Size         uint64 `json:"size" xml:"Size"`
	Name         string `json:"name" xml:"Name"`
	Value        string `json:"value" xml:"Value"`
	Domain       string `json:"domain" xml:"Domain"`
	Path         string `json:"path" xml:"Path"`
	Flags        string `json:"flags" xml:"Flags"`
	Expires      string `json:"expires" xml:"Expires"`
	LastAccessed string `json:"lastAccessed" xml:"LastAccessed"`
}

// Command line flag variables
var file = flag.String("i", "", "path to the binary cookies file")
var version = flag.Bool("v", false, "display version number")
var debug = flag.Bool("d", false, "display debugging information")
var format = flag.String("f", "table", "format of output [table|list|json|csv|xml]")

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

	// This variable will hold all the decoded cookies for later use
	var allCookies []cookie

	// At this point, the pages have been extracted, and the cookies extracted from the pages, so last step is to just
	// decode the cookies in each page
	decodeCookies(pages, &allCookies)

	// Based on the format, output the cookie data
	switch *format {
	case "table":
		outputAsTable(allCookies)
	case "list":
		outputAsList(allCookies)
	case "json":
		outputAsJSON(allCookies)
	case "csv":
		outputAsCSV(allCookies)
	case "xml":
		outputAsXML(allCookies)
	default:
		fmt.Printf("This should never run\n")
	}
}

// This function takes a slice of cookies and prints them out in a table format
func outputAsTable(cookies []cookie) {
	for i := 0; i < len(cookies); i++ {
		fmt.Printf("Cookie %d: %s=", i+1, cookies[i].Name)
		fmt.Printf("%s; ", cookies[i].Value)
		fmt.Printf("Domain: %s; ", cookies[i].Domain)
		fmt.Printf("Path: %s; ", cookies[i].Path)
		fmt.Printf("Expires: %v; ", cookies[i].Expires)
		fmt.Printf("Last Accessed: %v; ", cookies[i].LastAccessed)
		fmt.Printf("%s\n", cookies[i].Flags)
	}
}

// This function takes a slice of cookies and prints them out in a list format
func outputAsList(cookies []cookie) {
	for i := 0; i < len(cookies); i++ {
		fmt.Printf("Name: %s\n", cookies[i].Name)
		fmt.Printf("Value: %s\n", cookies[i].Value)
		fmt.Printf("Domain: %s\n", cookies[i].Domain)
		fmt.Printf("Path: %s\n", cookies[i].Path)
		fmt.Printf("Expires: %v\n", cookies[i].Expires)
		fmt.Printf("Last Accessed: %v\n", cookies[i].LastAccessed)
		fmt.Printf("Flags: %s\n\n", cookies[i].Flags)
	}
}

// This function takes a slice of cookies and prints them out as a XML chunk
func outputAsXML(cookies []cookie) {
	type Nesting struct {
		XMLName xml.Name `xml:"Cookies"`
		Cookie  []cookie
	}

	nesting := &Nesting{}
	nesting.Cookie = cookies

	out, _ := xml.MarshalIndent(nesting, "", "	")
	fmt.Println(xml.Header + string(out))
}

// This function takes a slice of cookies and prints them out as a JSON chunk
func outputAsJSON(cookies []cookie) {
	marshalled, _ := json.Marshal(cookies)
	fmt.Println(string(marshalled))
}

// This method will take a slice of cookie objects and output the data in CSV format. Handy for piping into a CSV file for analysis
func outputAsCSV(cookies []cookie) {
	// First, create the records as a [][]string
	var result [][]string
	headers := []string{"name", "value", "domain", "path", "expires", "lastAccessed", "flags"}
	result = append(result, headers)

	for i := 0; i < len(cookies); i++ {
		var row []string
		row = append(row, cookies[i].Name)
		row = append(row, cookies[i].Value)
		row = append(row, cookies[i].Domain)
		row = append(row, cookies[i].Path)
		row = append(row, cookies[i].Expires)
		row = append(row, cookies[i].LastAccessed)
		row = append(row, cookies[i].Flags)
		result = append(result, row)
	}

	w := csv.NewWriter(os.Stdout)

	for _, record := range result {
		err := w.Write(record)
		handleError(err)
	}

	w.Flush()

	if err := w.Error(); err != nil {
		handleError(err)
	}
}

// This function takes a pages object and will decode the cookies within the individual pages. Nothing is returned as it
// modifies the objects the pages reference points to
func decodeCookies(pages pages, allCookies *[]cookie) {
	// First, loop through the pages
	for i := 0; i < len(pages.pages); i++ {
		// Now, loop through the cookies within each page
		for j := 0; j < len(pages.pages[i].cookies); j++ {
			// And here you can access each cookie object individually, so decode them and update each cookies instance variables
			// Decode size of individual cookies
			a := pages.pages[i].cookies[j].rawBytes[:4]
			intA := int(convertHexToUint(reverseByteSlice(a)))
			pages.pages[i].cookies[j].Size = uint64(intA)

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
			pages.pages[i].cookies[j].Flags = flagText

			// Determine offsets for the other values (needed to know where to carve values from)
			domainOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[16:20])) // 4 byte field
			nameOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[20:24]))   // 4 byte field
			pathOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[24:28]))   // 4 byte field
			valueOffset := convertHexToUint(reverseByteSlice(pages.pages[i].cookies[j].rawBytes[28:32]))  // 4 byte field

			// Carve the values from the raw cookie bytes using the above offsets, and set the cookie instance variables to the carved values
			// Each value is null terminated and variable in length, so scanUntilNullByte grabs everything from the offset until it sees 0x00
			pages.pages[i].cookies[j].Name = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[nameOffset:]))
			pages.pages[i].cookies[j].Value = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[valueOffset:]))
			pages.pages[i].cookies[j].Domain = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[domainOffset:]))
			pages.pages[i].cookies[j].Path = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[pathOffset:]))

			// Now for the timestamps. These are big-endian double precision (or float64 in Go) values of Cocoa Core Data epochs
			expiresRaw := pages.pages[i].cookies[j].rawBytes[40:48]      // 8 byte field
			lastAccessedRaw := pages.pages[i].cookies[j].rawBytes[48:56] // 8 byte field
			pages.pages[i].cookies[j].Expires = convertCoreDataToString(convertHexToCoreDataTime(expiresRaw))
			pages.pages[i].cookies[j].LastAccessed = convertCoreDataToString(convertHexToCoreDataTime(lastAccessedRaw))

			// Build up an cookie object and put it into the cookies slice
			var aCookie cookie
			aCookie.rawBytes = pages.pages[i].cookies[j].rawBytes
			aCookie.Size = uint64(intA)
			aCookie.Name = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[nameOffset:]))
			aCookie.Value = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[valueOffset:]))
			aCookie.Domain = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[domainOffset:]))
			aCookie.Path = string(scanUntilNullByte(pages.pages[i].cookies[j].rawBytes[pathOffset:]))
			aCookie.Flags = flagText
			aCookie.Expires = convertCoreDataToString(convertHexToCoreDataTime(expiresRaw))
			aCookie.LastAccessed = convertCoreDataToString(convertHexToCoreDataTime(lastAccessedRaw))

			// Put the cookie object into the global cookies slice
			*allCookies = append(*allCookies, aCookie)
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

// Helper method to convert time.Time type to string type (to ease output formatting)
func convertCoreDataToString(time time.Time) string {
	return time.String()
}

func parseComLineFlags() {
	flag.Parse()

	if *version {
		fmt.Println("BinaryCookieExtractor (v1.0) - @KittyNighthawk (2021)")
		os.Exit(1)
	}

	if *file == "" {
		fmt.Println("No parameters supplied!")
		printUsageInstructions()
		os.Exit(1)
	}

	if *format != "table" && *format != "list" && *format != "json" && *format != "csv" && *format != "xml" {
		if *debug {
			fmt.Printf("[DEBUG] *format does not equal table, list, json, csv, or xml\n")
			fmt.Printf("[DEBUG] *format: %s\n", *format)
		}
		printUsageInstructions()
		os.Exit(1)
	}
}

func printUsageInstructions() {
	fmt.Println(`BinaryCookieExtractor (v1.0) - Safari/iOS/iPadOS Binary Cookie Decoder - @KittyNighthawk (2021)

Usage: $ ./binary-cookie-extractor -i <BINARY-COOKIE-FILE> [-f table|list|json|csv|xml] [-d]
Example: $ ./binary-cookie-extractor -i Cookies.binarycookies

For help, enter: $ ./binary-cookie-extractor -h`)
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

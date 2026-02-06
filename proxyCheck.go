package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type CheckResult struct {
	OriginalLine string
	IP           string
	Country      string
	ResponseTime float64
	Success      bool
	Error        string
}

type JSONResponse struct {
	Proxy struct {
		IP string `json:"ip"`
	} `json:"proxy"`
	Country struct {
		Name string `json:"name"`
	} `json:"country"`
}

func main() {
	var inputFile string
	var outputFile string
	var concurrency int
	var targetURL string
	var protocol string
	var showHelp bool
	var verbose bool

	// Custom Usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -i, --input string    Path to the input CSV file containing proxies (default \"data.csv\")")
		fmt.Fprintln(os.Stderr, "  -o, --output string   Path to the output CSV file (default \"proxy_details.csv\")")
		fmt.Fprintln(os.Stderr, "  -t, --threads int     Number of concurrent threads (default 500)")
		fmt.Fprintln(os.Stderr, "  -p, --protocol string Proxy protocol: socks5, http, https (default \"socks5\")")
		fmt.Fprintln(os.Stderr, "      --target string   Target URL to check proxies against (default \"https://ip.decodo.com/json\")")
		fmt.Fprintln(os.Stderr, "  -v, --verbose         Show detailed error logs")
		fmt.Fprintln(os.Stderr, "  -h, --help            Show help message")
	}

	// Input file
	flag.StringVar(&inputFile, "input", "data.csv", "")
	flag.StringVar(&inputFile, "i", "data.csv", "")

	// Output file
	flag.StringVar(&outputFile, "output", "proxy_details.csv", "")
	flag.StringVar(&outputFile, "o", "proxy_details.csv", "")

	// Threads
	flag.IntVar(&concurrency, "threads", 500, "")
	flag.IntVar(&concurrency, "t", 500, "")

	// Protocol
	flag.StringVar(&protocol, "protocol", "socks5", "")
	flag.StringVar(&protocol, "p", "socks5", "")

	// Target
	flag.StringVar(&targetURL, "target", "https://ip.decodo.com/json", "")

	// Verbose
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&verbose, "v", false, "")

	// Help
	flag.BoolVar(&showHelp, "help", false, "")
	flag.BoolVar(&showHelp, "h", false, "")

	flag.Parse()

	if showHelp {
		flag.Usage()
		return
	}

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", inputFile, err)
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	totalProxies := len(lines)
	fmt.Printf("Starting check for %d proxies with %d goroutines using %s...\n", totalProxies, concurrency, protocol)

	resultsChan := make(chan CheckResult, totalProxies)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	counter := 0
	var mu sync.Mutex

	for _, line := range lines {
		wg.Add(1)
		sem <- struct{}{}
		go func(l string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := checkProxy(l, targetURL, protocol)

			mu.Lock()
			counter++
			if verbose && res.Error != "" {
				fmt.Printf("\n[ERROR] %s: %s\n", res.OriginalLine, res.Error)
			}
			fmt.Printf("\rChecked %d/%d (Working: %s)         ", counter, totalProxies, res.IP)
			mu.Unlock()

			resultsChan <- res
		}(line)
	}

	wg.Wait()
	close(resultsChan)
	fmt.Println("\n\nProcessing results...")

	var workingResults []CheckResult
	countryCounts := make(map[string]int)
	var totalTime float64

	for res := range resultsChan {
		if res.Success {
			workingResults = append(workingResults, res)
			countryCounts[res.Country]++
			totalTime += res.ResponseTime
		}
	}

	// save CSV
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Failed to create %s: %v\n", outputFile, err)
		return
	}
	defer outFile.Close()

	writer := csv.NewWriter(outFile)
	defer writer.Flush()

	writer.Write([]string{"original_line", "ip", "country", "response_time"})
	for _, res := range workingResults {
		writer.Write([]string{
			res.OriginalLine,
			res.IP,
			res.Country,
			fmt.Sprintf("%.4f", res.ResponseTime),
		})
	}

	// print Summary
	totalWorking := len(workingResults)
	avgTime := 0.0
	if totalWorking > 0 {
		avgTime = totalTime / float64(totalWorking)
	}

	fmt.Println(strings.Repeat("-", 30))
	fmt.Printf("Total Working Proxies: %d\n", totalWorking)
	fmt.Printf("Average Response Time: %.2fs\n", avgTime)
	fmt.Println(strings.Repeat("-", 30))
	fmt.Println("By Country:")

	// sort countries by count
	type CountryCount struct {
		Name  string
		Count int
	}
	var sortedCountries []CountryCount
	for name, count := range countryCounts {
		sortedCountries = append(sortedCountries, CountryCount{name, count})
	}
	sort.Slice(sortedCountries, func(i, j int) bool {
		return sortedCountries[i].Count > sortedCountries[j].Count
	})

	for _, cc := range sortedCountries {
		fmt.Printf("%s: %d\n", cc.Name, cc.Count)
	}
	fmt.Println(strings.Repeat("-", 30))
	fmt.Printf("Detailed results saved to '%s'\n", outputFile)
}

func checkProxy(line, targetURL, protocol string) CheckResult {
	res := CheckResult{OriginalLine: line}

	var host, port, user, pass string

	toParse := line
	if strings.HasPrefix(toParse, "socks5://") {
		toParse = strings.TrimPrefix(toParse, "socks5://")
	} else if strings.HasPrefix(toParse, "socks5h://") {
		toParse = strings.TrimPrefix(toParse, "socks5h://")
	} else if strings.HasPrefix(toParse, "http://") {
		toParse = strings.TrimPrefix(toParse, "http://")
	} else if strings.HasPrefix(toParse, "https://") {
		toParse = strings.TrimPrefix(toParse, "https://")
	}

	if strings.Contains(toParse, "@") {
		parts := strings.SplitN(toParse, "@", 2)
		authPart := parts[0]
		addrPart := parts[1]
		authParts := strings.SplitN(authPart, ":", 2)
		if len(authParts) == 2 {
			user, pass = authParts[0], authParts[1]
		}
		addrParts := strings.SplitN(addrPart, ":", 2)
		if len(addrParts) == 2 {
			host, port = addrParts[0], addrParts[1]
		}
	} else {
		parts := strings.Split(toParse, ":")
		if len(parts) == 4 {
			host, port, user, pass = parts[0], parts[1], parts[2], parts[3]
		} else if len(parts) == 2 {
			host, port = parts[0], parts[1]
		} else {
			res.Error = "Invalid format"
			return res
		}
	}

	if strings.Contains(pass, ",") {
		pass = strings.Split(pass, ",")[0]
	}
	if strings.Contains(port, ",") {
		port = strings.Split(port, ",")[0]
	}

	if host == "" || port == "" {
		res.Error = "Empty host or port"
		return res
	}

	var transport *http.Transport

	if strings.ToLower(protocol) == "http" || strings.ToLower(protocol) == "https" {
		// HTTP
		proxyURLStr := fmt.Sprintf("http://%s:%s", host, port)
		if user != "" && pass != "" {
			proxyURLStr = fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, port)
		}
		
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			res.Error = fmt.Sprintf("URL parse error: %v", err)
			return res
		}

		transport = &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		}

	} else {
		// SOCKS5
		var auth *proxy.Auth
		if user != "" && pass != "" {
			auth = &proxy.Auth{User: user, Password: pass}
		}

		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", host, port), auth, proxy.Direct)
		if err != nil {
			res.Error = fmt.Sprintf("SOCKS5 dialer error: %v", err)
			return res
		}

		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(targetURL)
	duration := time.Since(start).Seconds()
	res.ResponseTime = duration

	if err != nil {
		res.Error = fmt.Sprintf("Connection error: %v", err)
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			var jsonResp JSONResponse
			if err := json.Unmarshal(body, &jsonResp); err == nil {
				res.Success = true
				res.IP = jsonResp.Proxy.IP
				res.Country = jsonResp.Country.Name
			}
		}
	} else {
		res.Error = fmt.Sprintf("Status code: %d", resp.StatusCode)
	}

	return res
}

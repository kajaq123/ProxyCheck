package main

import (
    "bufio"
    "context"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
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
    inputFile := "data.csv"
    outputFile := "proxy_details.csv"
    concurrency := 500
    targetURL := "https://ip.decodo.com/json"

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
    fmt.Printf("Starting check for %d proxies with %d goroutines...\n", totalProxies, concurrency)

    resultsChan := make(chan CheckResult, totalProxies)
    var wg sync.WaitGroup
    sem := make(chan struct{}, concurrency)

    counter := 0
    var mu sync.Mutex

    for _, line := range lines {
        wg.Add(1)
        sem <- struct{}{} // Acquire semaphore
        go func(l string) {
            defer wg.Done()
            defer func() { <-sem }() // Release

            res := checkProxy(l, targetURL)

            mu.Lock()
            counter++
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

    // Save to CSV
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

    // Print Summary
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

    // Sort countries by count
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

func checkProxy(line, targetURL string) CheckResult {
	res := CheckResult{OriginalLine: line}

	var host, port, user, pass string

	if strings.HasPrefix(line, "socks5h://") {
		trimmed := strings.TrimPrefix(line, "socks5h://")
		if strings.Contains(trimmed, "@") {
			parts := strings.SplitN(trimmed, "@", 2)
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
			addrParts := strings.SplitN(trimmed, ":", 2)
			if len(addrParts) == 2 {
				host, port = addrParts[0], addrParts[1]
			}
		}
	} else if strings.HasPrefix(line, "socks5://") {
		trimmed := strings.TrimPrefix(line, "socks5://")
		if strings.Contains(trimmed, "@") {
			parts := strings.SplitN(trimmed, "@", 2)
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
			addrParts := strings.SplitN(trimmed, ":", 2)
			if len(addrParts) == 2 {
				host, port = addrParts[0], addrParts[1]
			}
		}
	} else {
		parts := strings.Split(line, ":")
		if len(parts) == 4 {
			host, port, user, pass = parts[0], parts[1], parts[2], parts[3]
		} else if len(parts) == 2 {
			host, port = parts[0], parts[1]
		} else {
			return res
		}
	}

	if host == "" || port == "" {
		return res
	}

	// Create SOCKS5 dialer
	var auth *proxy.Auth
	if user != "" && pass != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", host, port), auth, proxy.Direct)
	if err != nil {
		return res
	}

	// Create HTTP transport with the dialer
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
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
	}

	return res
}

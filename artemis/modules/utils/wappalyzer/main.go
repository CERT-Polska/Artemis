package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func scan(url string, wappalyzerClient *wappalyzer.Wappalyze) map[string][]string {
	result := make(map[string][]string)

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error fetching %s: %v\n", url, err)
		return result
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)

	techs := []string{}
	for tech := range fingerprints {
		techs = append(techs, tech)
	}
	result[url] = techs
	return result
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <path_to_urls_file>")
		os.Exit(1)
	}
	filePath := os.Args[1]

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("FATAL: Could not open file %s: %v\n", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if err := scanner.Err(); err != nil {
		log.Fatalf("FATAL: Error reading from file: %v\n", err)
	}

	urls := []string{}
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	wappalyzerClient, _ := wappalyzer.New()
	finalResults := make(map[string][]string)

	for _, url := range urls {
		result := scan(url, wappalyzerClient)
		for k, v := range result {
			finalResults[k] = v
		}
	}

	jsonOutput, err := json.MarshalIndent(finalResults, "", "  ")
	if err != nil {
		log.Fatalf("Error marshalling to JSON: %v\n", err)
	}

	log.Println(string(jsonOutput)) // Print the technologies found to the logs as well
	fmt.Println(string(jsonOutput))
}

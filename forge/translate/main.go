package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/schollz/progressbar/v3"
	"github.com/tidwall/gjson"
	"golang.org/x/sync/errgroup"
)

const (
	googleTranslateAPIURL = "https://translate.googleapis.com/translate_a/single"
	maxChunkRunes         = 4000
)

var (
	retryClient    *retryablehttp.Client
	targetLanguage string
	concurrency    int
)

type chunkInfo struct {
	text                    string
	needsParagraphSeparator bool
}

func init() {
	retryClient = retryablehttp.NewClient()
	retryClient.RetryMax = 5
	retryClient.RetryWaitMin = 500 * time.Millisecond
	retryClient.RetryWaitMax = 4 * time.Second
	retryClient.Logger = nil
}

func main() {
	log.SetFlags(log.LstdFlags)

	for _, argument := range os.Args[1:] {
		if argument == "-h" || argument == "--help" {
			printUsage()
		}
	}

	flag.StringVar(&targetLanguage, "tl", "en", "target language code (default: en)")
	flag.IntVar(&concurrency, "c", 4, "concurrency level (default: 4, recommended 3-6)")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Input file is required! Use -h for help.")
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 10 {
		log.Printf("Concurrency too high, may trigger rate limiting. Auto-capped at 10.")
		concurrency = 10
	}

	inputFile := flag.Arg(0)
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		log.Fatalf("File not found: %s", inputFile)
	}

	outputFile := generateOutputFilename(inputFile)
	log.Printf("Starting task: %s → %s (target: %s, concurrency: %d)", inputFile, outputFile, targetLanguage, concurrency)

	sourceContentBytes, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	sourceContent := string(sourceContentBytes)

	if strings.TrimSpace(sourceContent) == "" {
		log.Println("File is empty, copying as-is.")
		if err := os.WriteFile(outputFile, sourceContentBytes, 0644); err != nil {
			log.Printf("Failed to write output file: %v", err)
		}
		return
	}

	chunks := splitIntoChunks(sourceContent)

	if len(chunks) == 0 {
		log.Fatal("Failed to split into chunks.")
	}

	progressBar := progressbar.Default(int64(len(chunks)), "Translating")

	startTime := time.Now()
	var workerGroup errgroup.Group
	workerGroup.SetLimit(concurrency)

	translatedSegments := make([]string, len(chunks))
	var mutex sync.Mutex

	for index, chunk := range chunks {
		currentIndex := index
		currentChunk := chunk
		workerGroup.Go(func() error {
			translatedText := currentChunk.text
			if strings.TrimSpace(currentChunk.text) != "" {
				var err error
				translatedText, err = translateChunk(currentChunk.text)
				if err != nil {
					log.Printf("Chunk %d failed: %v → keeping original", currentIndex, err)
					translatedText = currentChunk.text
				}
			}
			mutex.Lock()
			translatedSegments[currentIndex] = translatedText
			mutex.Unlock()

			_ = progressBar.Add(1)

			time.Sleep(time.Duration(rand.Intn(600)+400) * time.Millisecond)
			return nil
		})
	}

	if err := workerGroup.Wait(); err != nil {
		log.Fatalf("Concurrency error: %v", err)
	}

	var finalBuilder strings.Builder
	for index, result := range translatedSegments {
		finalBuilder.WriteString(result)
		if chunks[index].needsParagraphSeparator {
			finalBuilder.WriteString("\n\n")
		}
	}

	finalTranslatedText := postProcess(finalBuilder.String())

	if err := os.WriteFile(outputFile, []byte(finalTranslatedText), 0644); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	totalRunes := len([]rune(sourceContent))
	elapsedDuration := time.Since(startTime)
	log.Printf("Done! Saved to: %s", outputFile)
	log.Printf("Stats → Characters: %d | Time: %s | Speed: %.0f chars/sec",
		totalRunes, elapsedDuration.Round(time.Second), float64(totalRunes)/elapsedDuration.Seconds())
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `
translate - Advanced free Google Translate CLI tool (2026 Ultimate Edition)

Usage:
  translate [options] <input_file>

Options:
  -h, --help              Show this help message
  -tl <code>              Target language (default: en)
  -c <num>                Concurrency level (default: 4, recommended 3-6)

Examples:
  translate -tl en -c 5 novel.txt
  translate -tl fr docs.md
`)
	os.Exit(0)
}

func splitIntoChunks(text string) []chunkInfo {
	var chunks []chunkInfo
	paragraphs := strings.Split(text, "\n\n")

	for paragraphIndex, paragraph := range paragraphs {
		trimmedParagraph := strings.TrimSpace(paragraph)
		if trimmedParagraph == "" {
			chunks = append(chunks, chunkInfo{text: "", needsParagraphSeparator: true})
			continue
		}

		lines := strings.Split(paragraph, "\n")
		var chunkBuilder strings.Builder

		for _, line := range lines {
			testChunk := line
			if chunkBuilder.Len() > 0 {
				testChunk = "\n" + line
			}
			if len([]rune(chunkBuilder.String()+testChunk)) > maxChunkRunes && chunkBuilder.Len() > 0 {
				chunks = append(chunks, chunkInfo{text: chunkBuilder.String(), needsParagraphSeparator: false})
				chunkBuilder.Reset()
			}
			if chunkBuilder.Len() > 0 {
				chunkBuilder.WriteString("\n")
			}
			chunkBuilder.WriteString(line)
		}

		if chunkBuilder.Len() > 0 {
			shouldAddSeparator := paragraphIndex < len(paragraphs)-1
			chunks = append(chunks, chunkInfo{text: chunkBuilder.String(), needsParagraphSeparator: shouldAddSeparator})
		}
	}
	return chunks
}

func translateChunk(text string) (string, error) {
	queryParams := url.Values{
		"client": {"gtx"},
		"sl":     {"auto"},
		"tl":     {targetLanguage},
		"dt":     {"t"},
		"q":      {text},
	}

	request, err := retryablehttp.NewRequest("GET", googleTranslateAPIURL+"?"+queryParams.Encode(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	request.Header.Set("Referer", "https://translate.google.com/")

	response, err := retryClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", response.StatusCode)
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var translationBuilder strings.Builder
	gjson.Get(string(responseBody), "0").ForEach(func(_, sentence gjson.Result) bool {
		if sentence.IsArray() && sentence.Array()[0].Exists() {
			translationBuilder.WriteString(sentence.Array()[0].String())
		}
		return true
	})

	result := translationBuilder.String()
	return result, nil
}

func postProcess(text string) string {
	var cleanedLines []string
	for _, line := range strings.Split(text, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			if len(cleanedLines) == 0 || cleanedLines[len(cleanedLines)-1] != "" {
				cleanedLines = append(cleanedLines, "")
			}
		} else {
			cleanedLines = append(cleanedLines, trimmedLine)
		}
	}
	return strings.Join(cleanedLines, "\n")
}

func generateOutputFilename(path string) string {
	fileExtension := filepath.Ext(path)
	fileNameWithoutExt := strings.TrimSuffix(path, fileExtension)
	return fileNameWithoutExt + "_" + targetLanguage + fileExtension
}

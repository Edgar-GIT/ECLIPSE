package garbageinjector

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"programa/utils"
)

const (
	outputDir = "./Garbage_Output"
)

func GarbageInjector() {
	for {
		utils.ClearTerminal()
		showGarbageMenu()

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("%sChoose an option: %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			injectGarbageToFile()
		case "2":
			viewOutputDirectory()
		case "3":
			cleanOutputDirectory()
		case "4":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
		}
	}
}

func showGarbageMenu() {
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s║                  GARBAGE INJECTOR                             ║%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Purple, utils.Reset)

	fmt.Printf("%s  [1] Inject Garbage into File%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] View Output Directory%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s  [3] Clean Output Directory%s\n", utils.Yellow, utils.Reset)
	utils.PrintReturnOption("4")
}

func injectGarbageToFile() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ GARBAGE INJECTION ═══%s\n\n", utils.Purple, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sEnter file path to bloat: %s", utils.Green, utils.Reset)
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	if filePath == "" {
		fmt.Printf("%s[!] No file path provided%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("%s[!] File not found: %s%s\n", utils.Red, filePath, utils.Reset)
		utils.PauseForInput()
		return
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("%s[!] Cannot read file info: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	currentSizeMB := float64(fileInfo.Size()) / (1024 * 1024)

	fmt.Printf("\n%s[i] Original file: %s%s\n", utils.Blue, filepath.Base(filePath), utils.Reset)
	fmt.Printf("%s[i] Current size: %.2f MB (%.0f bytes)%s\n\n", utils.Blue, currentSizeMB, float64(fileInfo.Size()), utils.Reset)

	fmt.Printf("%sTarget size in MB (must be larger than %.2f MB): %s", utils.Green, currentSizeMB, utils.Reset)
	targetInput, _ := reader.ReadString('\n')
	targetInput = strings.TrimSpace(targetInput)

	var targetMB float64
	_, err = fmt.Sscanf(targetInput, "%f", &targetMB)
	if err != nil {
		fmt.Printf("%s[!] Invalid size format%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	if targetMB <= currentSizeMB {
		fmt.Printf("%s[!] Target size must be larger than current size (%.2f MB)%s\n", utils.Red, currentSizeMB, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%sOutput filename (without extension): %s", utils.Green, utils.Reset)
	outputName, _ := reader.ReadString('\n')
	outputName = strings.TrimSpace(outputName)

	if outputName == "" {
		outputName = "bloated_" + strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	}

	extension := filepath.Ext(filePath)
	outputFilename := outputName + extension

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%s[!] Failed to create output directory: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	outputPath := filepath.Join(outputDir, outputFilename)

	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s║                    INJECTION SUMMARY                          ║%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Yellow, utils.Reset)

	fmt.Printf("%s  Original File:    %s%s\n", utils.Blue, filepath.Base(filePath), utils.Reset)
	fmt.Printf("%s  Original Size:    %.2f MB%s\n", utils.Blue, currentSizeMB, utils.Reset)
	fmt.Printf("%s  Target Size:      %.2f MB%s\n", utils.Blue, targetMB, utils.Reset)
	fmt.Printf("%s  Garbage to Add:   %.2f MB%s\n", utils.Blue, targetMB-currentSizeMB, utils.Reset)
	fmt.Printf("%s  Output File:      %s%s\n", utils.Blue, outputFilename, utils.Reset)
	fmt.Printf("%s  Output Path:      %s%s\n\n", utils.Blue, outputPath, utils.Reset)

	fmt.Printf("%sProceed with injection? (y/n): %s", utils.Yellow, utils.Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))

	if confirm != "y" && confirm != "yes" {
		fmt.Printf("%s[!] Operation cancelled%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%s[*] Starting garbage injection...%s\n\n", utils.Yellow, utils.Reset)

	err = performGarbageInjection(filePath, outputPath, targetMB)
	if err != nil {
		fmt.Printf("\n%s[!] Injection failed: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	finalInfo, _ := os.Stat(outputPath)
	finalSizeMB := float64(finalInfo.Size()) / (1024 * 1024)

	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s║                    INJECTION COMPLETE                         ║%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Green, utils.Reset)

	fmt.Printf("%s  [✓] File successfully bloated!%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [✓] Final size: %.2f MB%s\n", utils.Green, finalSizeMB, utils.Reset)
	fmt.Printf("%s  [✓] Saved to: %s%s\n\n", utils.Green, outputPath, utils.Reset)

	if finalSizeMB > 32 {
		fmt.Printf("%s  [i] File is too large for VirusTotal free (32MB limit)%s\n", utils.Blue, utils.Reset)
	}
	if finalSizeMB > 100 {
		fmt.Printf("%s  [i] File is too large for most online sandboxes%s\n", utils.Blue, utils.Reset)
	}

	utils.PauseForInput()
}

func performGarbageInjection(inputPath, outputPath string, targetMB float64) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	fmt.Printf("%s[1/3] Copying original file...%s\n", utils.Yellow, utils.Reset)

	copied, err := io.Copy(outputFile, inputFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	currentSize := copied
	targetSize := int64(targetMB * 1024 * 1024)
	garbageSize := targetSize - currentSize

	if garbageSize <= 0 {
		return fmt.Errorf("file already equals or exceeds target size")
	}

	fmt.Printf("%s[✓] Original file copied (%.2f MB)%s\n", utils.Green, float64(copied)/(1024*1024), utils.Reset)
	fmt.Printf("\n%s[2/3] Generating garbage data...%s\n", utils.Yellow, utils.Reset)

	bufferSize := 1024 * 1024
	buffer := make([]byte, bufferSize)
	written := int64(0)

	lastProgress := -1

	for written < garbageSize {
		toWrite := int64(bufferSize)
		if written+toWrite > garbageSize {
			toWrite = garbageSize - written
		}

		_, err := rand.Read(buffer[:toWrite])
		if err != nil {
			return fmt.Errorf("failed to generate random data: %v", err)
		}

		n, err := outputFile.Write(buffer[:toWrite])
		if err != nil {
			return fmt.Errorf("failed to write garbage: %v", err)
		}

		written += int64(n)

		progress := int((float64(written) / float64(garbageSize)) * 100)
		if progress != lastProgress && progress%10 == 0 {
			fmt.Printf("%s[*] Progress: %d%% (%.2f MB / %.2f MB)%s\n",
				utils.Yellow,
				progress,
				float64(written)/(1024*1024),
				float64(garbageSize)/(1024*1024),
				utils.Reset)
			lastProgress = progress
		}
	}

	fmt.Printf("%s[✓] Garbage injection complete (%.2f MB added)%s\n", utils.Green, float64(written)/(1024*1024), utils.Reset)
	fmt.Printf("\n%s[3/3] Finalizing file...%s\n", utils.Yellow, utils.Reset)

	err = outputFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file: %v", err)
	}

	fmt.Printf("%s[✓] File finalized%s\n", utils.Green, utils.Reset)

	return nil
}

func viewOutputDirectory() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ OUTPUT DIRECTORY ═══%s\n\n", utils.Blue, utils.Reset)

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		fmt.Printf("%s[i] Output directory is empty (not created yet)%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	files, err := os.ReadDir(outputDir)
	if err != nil {
		fmt.Printf("%s[!] Failed to read directory: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	if len(files) == 0 {
		fmt.Printf("%s[i] No files in output directory%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("%sFiles in %s:%s\n\n", utils.Green, outputDir, utils.Reset)

	totalSize := int64(0)

	for i, file := range files {
		if file.IsDir() {
			continue
		}

		fullPath := filepath.Join(outputDir, file.Name())
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		sizeMB := float64(info.Size()) / (1024 * 1024)
		totalSize += info.Size()

		fmt.Printf("%s[%d] %s%s\n", utils.Blue, i+1, file.Name(), utils.Reset)
		fmt.Printf("    Size: %.2f MB (%.0f bytes)\n", sizeMB, float64(info.Size()))
		fmt.Printf("    Modified: %s\n\n", info.ModTime().Format("2006-01-02 15:04:05"))
	}

	totalSizeMB := float64(totalSize) / (1024 * 1024)
	fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%sTotal: %d files, %.2f MB%s\n", utils.Green, len(files), totalSizeMB, utils.Reset)

	utils.PauseForInput()
}

func cleanOutputDirectory() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ CLEAN OUTPUT DIRECTORY ═══%s\n\n", utils.Yellow, utils.Reset)

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		fmt.Printf("%s[i] Output directory does not exist%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	files, err := os.ReadDir(outputDir)
	if err != nil {
		fmt.Printf("%s[!] Failed to read directory: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	if len(files) == 0 {
		fmt.Printf("%s[i] Directory is already empty%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("%s[!] This will delete %d file(s) from %s%s\n", utils.Red, len(files), outputDir, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sAre you sure? (y/n): %s", utils.Yellow, utils.Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))

	if confirm != "y" && confirm != "yes" {
		fmt.Printf("%s[!] Operation cancelled%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	deleted := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fullPath := filepath.Join(outputDir, file.Name())
		err := os.Remove(fullPath)
		if err != nil {
			fmt.Printf("%s[!] Failed to delete %s: %v%s\n", utils.Red, file.Name(), err, utils.Reset)
		} else {
			fmt.Printf("%s[✓] Deleted: %s%s\n", utils.Green, file.Name(), utils.Reset)
			deleted++
		}
	}

	fmt.Printf("\n%s[✓] Cleaned %d file(s)%s\n", utils.Green, deleted, utils.Reset)
	utils.PauseForInput()
}

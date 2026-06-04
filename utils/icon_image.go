package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func SelectIconImage(reader *bufio.Reader, imgDir string) string {
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}

	if strings.TrimSpace(imgDir) == "" {
		imgDir = "img"
	}
	imgDir = filepath.Clean(imgDir)

	if err := os.MkdirAll(imgDir, 0755); err != nil {
		fmt.Printf("%s[!] Could not create img folder: %v%s\n", Yellow, err, Reset)
		return ""
	}

	for {
		fmt.Printf("\n%sImage source:%s\n", Blue, Reset)
		fmt.Printf("%s  [1] Choose from img folder%s\n", Green, Reset)
		fmt.Printf("%s  [2] Provide image path%s\n", Green, Reset)
		fmt.Printf("%s  [3] Open file explorer%s\n", Green, Reset)
		fmt.Printf("%s  [0] Skip image%s\n", Yellow, Reset)
		fmt.Printf("%sOption: %s", Green, Reset)

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			selected, err := selectIconImageFromDir(reader, imgDir)
			if err != nil {
				fmt.Printf("%s[!] %v%s\n", Yellow, err, Reset)
				continue
			}
			return selected
		case "2":
			selected, err := readIconImagePath(reader)
			if err != nil {
				fmt.Printf("%s[!] %v%s\n", Red, err, Reset)
				continue
			}
			return selected
		case "3":
			selected, err := pickIconImageFile(imgDir)
			if err != nil {
				fmt.Printf("%s[!] File explorer unavailable or cancelled: %v%s\n", Yellow, err, Reset)
				continue
			}
			return selected
		case "0", "":
			return ""
		default:
			fmt.Printf("%sInvalid option!%s\n", Red, Reset)
		}
	}
}

func selectIconImageFromDir(reader *bufio.Reader, imgDir string) (string, error) {
	icons, err := listIconImages(imgDir)
	if err != nil {
		return "", err
	}
	if len(icons) == 0 {
		return "", fmt.Errorf("no image files found in %s", imgDir)
	}

	fmt.Printf("\n%sAvailable images:%s\n", Blue, Reset)
	for i, icon := range icons {
		fmt.Printf("%s  [%d] %s%s\n", Green, i+1, icon, Reset)
	}
	fmt.Printf("%s  [0] Back%s\n", Yellow, Reset)
	fmt.Printf("\n%sSelect image number: %s", Green, Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "0" || input == "" {
		return "", fmt.Errorf("selection cancelled")
	}

	var choice int
	if _, err := fmt.Sscanf(input, "%d", &choice); err != nil || choice < 1 || choice > len(icons) {
		return "", fmt.Errorf("invalid image selection")
	}

	return filepath.Join(imgDir, icons[choice-1]), nil
}

func readIconImagePath(reader *bufio.Reader) (string, error) {
	fmt.Printf("%sImage path: %s", Green, Reset)
	input, _ := reader.ReadString('\n')
	return ValidateIconImagePath(input)
}

func pickIconImageFile(defaultDir string) (string, error) {
	selected, err := PickOpenFile(FilePickerConfig{
		Title:      "Select image",
		DefaultDir: defaultDir,
		FileFilter: iconImageFileFilter(),
	})
	if err != nil {
		return "", err
	}
	return ValidateIconImagePath(selected)
}

func listIconImages(imgDir string) ([]string, error) {
	files, err := os.ReadDir(imgDir)
	if err != nil {
		return nil, err
	}

	icons := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if SupportedIconImageExt(file.Name()) {
			icons = append(icons, file.Name())
		}
	}
	sort.Strings(icons)
	return icons, nil
}

func ValidateIconImagePath(input string) (string, error) {
	path := cleanPastedPath(input)
	if path == "" {
		return "", fmt.Errorf("image path cannot be empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("image file not found: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("image path is a directory")
	}
	if !SupportedIconImageExt(path) {
		return "", fmt.Errorf("unsupported image format: %s", filepath.Ext(path))
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return abs, nil
}

func SupportedIconImageExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ico", ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp":
		return true
	default:
		return false
	}
}

func MaterializeICO(srcPath string) (string, func(), error) {
	cleanPath, err := ValidateIconImagePath(srcPath)
	if err != nil {
		return "", nil, err
	}

	if strings.EqualFold(filepath.Ext(cleanPath), ".ico") {
		return cleanPath, func() {}, nil
	}

	tmpFile, err := os.CreateTemp("", "eclipse-icon-*.ico")
	if err != nil {
		return "", nil, err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", nil, err
	}

	var lastErr error
	for _, args := range iconConvertAttempts(cleanPath, tmpPath) {
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.CombinedOutput()
		if err == nil {
			return tmpPath, func() { _ = os.Remove(tmpPath) }, nil
		}
		if len(output) > 0 {
			lastErr = fmt.Errorf("%v: %w: %s", args, err, strings.TrimSpace(string(output)))
		} else {
			lastErr = fmt.Errorf("%v: %w", args, err)
		}
	}

	_ = os.Remove(tmpPath)
	if lastErr != nil {
		return "", nil, fmt.Errorf("failed to convert image to .ico; install ImageMagick: %w", lastErr)
	}
	return "", nil, fmt.Errorf("failed to convert image to .ico; install ImageMagick")
}

func iconConvertAttempts(srcPath, outPath string) [][]string {
	return [][]string{
		{"magick", srcPath, "-resize", "256x256", outPath},
		{"magick", "convert", srcPath, "-resize", "256x256", outPath},
		{"convert", srcPath, "-resize", "256x256", outPath},
	}
}

func cleanPastedPath(input string) string {
	path := strings.TrimSpace(input)
	path = strings.Trim(path, "\"'")
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func iconImageFileFilter() string {
	if runtime.GOOS == "windows" {
		return "Image Files (*.ico;*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff;*.webp)|*.ico;*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff;*.webp|All Files (*.*)|*.*"
	}
	return "Image files | *.ico *.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff *.webp"
}

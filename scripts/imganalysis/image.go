package imganalysis

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"programa/utils"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	imageReportsDir  = "image_reports"
	imageHistoryFile = "image_analysis_history.json"
)

type FileHashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type ImageAnalysisRecord struct {
	AnalyzedAt               time.Time              `json:"analyzed_at"`
	ImagePath                string                 `json:"image_path"`
	ImageName                string                 `json:"image_name"`
	Extension                string                 `json:"extension"`
	SizeBytes                int64                  `json:"size_bytes"`
	SizeHuman                string                 `json:"size_human"`
	Permissions              string                 `json:"permissions"`
	ModifiedAt               time.Time              `json:"modified_at"`
	MIMEType                 string                 `json:"mime_type"`
	MagicBytes               string                 `json:"magic_bytes"`
	DecoderFormat            string                 `json:"decoder_format,omitempty"`
	Width                    int                    `json:"width,omitempty"`
	Height                   int                    `json:"height,omitempty"`
	ColorModel               string                 `json:"color_model,omitempty"`
	EntropyBitsPerByte       *float64               `json:"entropy_bits_per_byte,omitempty"`
	GPSLatitude              *float64               `json:"gps_latitude,omitempty"`
	GPSLongitude             *float64               `json:"gps_longitude,omitempty"`
	GPSCoordinatesSource     string                 `json:"gps_coordinates_source,omitempty"`
	GeoLookupAttempted       bool                   `json:"geo_lookup_attempted"`
	GeoLookupProvider        string                 `json:"geo_lookup_provider,omitempty"`
	GeoLookupError           string                 `json:"geo_lookup_error,omitempty"`
	GeoDisplayName           string                 `json:"geo_display_name,omitempty"`
	GeoCountry               string                 `json:"geo_country,omitempty"`
	GeoRegion                string                 `json:"geo_region,omitempty"`
	GeoCity                  string                 `json:"geo_city,omitempty"`
	GeoPostcode              string                 `json:"geo_postcode,omitempty"`
	GeoMapURL                string                 `json:"geo_map_url,omitempty"`
	GeoGoogleMapsURL         string                 `json:"geo_google_maps_url,omitempty"`
	Hashes                   FileHashes             `json:"hashes"`
	ExifToolInstalled        bool                   `json:"exiftool_installed"`
	ExifToolInstallAttempted bool                   `json:"exiftool_install_attempted"`
	ExifToolInstallLog       string                 `json:"exiftool_install_log,omitempty"`
	ExifToolError            string                 `json:"exiftool_error,omitempty"`
	ExifMetadata             map[string]interface{} `json:"exif_metadata,omitempty"`
	ReportFile               string                 `json:"report_file,omitempty"`
}

type ImageAnalysisHistory struct {
	Analyses []ImageAnalysisRecord `json:"analyses"`
}

type ExifToolResult struct {
	Available        bool
	InstallAttempted bool
	InstallLog       string
	ErrorMessage     string
	Structured       map[string]interface{}
	StructuredPretty string
	GroupedText      string
}

type ImageAnalysisResult struct {
	Record ImageAnalysisRecord
	Report string
}

type ReverseGeoResult struct {
	Attempted   bool
	Provider    string
	DisplayName string
	Country     string
	Region      string
	City        string
	Postcode    string
	MapURL      string
	Error       string
}

func ImageAnalysis() {
	utils.ClearTerminal()

	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s║                    IMAGE ANALYSIS                             ║%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Purple, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	path, err := promptImagePath(reader)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	if path == "" {
		fmt.Printf("%s[!] Operation cancelled.%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%s[*] Analysing image...%s\n", utils.Yellow, utils.Reset)
	result, err := analyzeImage(path)
	if err != nil {
		fmt.Printf("%s[!] Failed to analyse image: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%s%s%s\n", utils.Blue, result.Report, utils.Reset)

	if savedPath, saveErr := saveImageReport(path, result.Report); saveErr == nil {
		result.Record.ReportFile = savedPath
		fmt.Printf("\n%s[✓] Report saved to: %s%s\n", utils.Green, savedPath, utils.Reset)
	} else {
		fmt.Printf("\n%s[!] Could not save report: %v%s\n", utils.Yellow, saveErr, utils.Reset)
	}

	if err := saveImageHistoryRecord(result.Record); err != nil {
		fmt.Printf("%s[!] Could not save JSON history: %v%s\n", utils.Yellow, err, utils.Reset)
	} else {
		fmt.Printf("%s[✓] JSON history updated: %s%s\n", utils.Green, imageHistoryFile, utils.Reset)
	}

	promptOpenMapAfterScan(reader, result.Record)

	utils.PauseForInput()
}

func ViewImageAnalysisHistory() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== IMAGE ANALYSIS HISTORY ===%s\n\n", utils.Blue, utils.Reset)

	history, err := loadImageHistory()
	if err != nil || len(history.Analyses) == 0 {
		fmt.Printf("%sNo image analysis history found. Run an image analysis first!%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("%sHistory entries (%d):%s\n", utils.Green, len(history.Analyses), utils.Reset)
	for i, rec := range history.Analyses {
		dateStr := rec.AnalyzedAt.Format("2006-01-02 15:04:05")
		dim := "N/A"
		if rec.Width > 0 && rec.Height > 0 {
			dim = fmt.Sprintf("%dx%d", rec.Width, rec.Height)
		}
		fmt.Printf("%s[%d]%s %s | %s | %s | %s\n", utils.Yellow, i+1, utils.Reset, dateStr, rec.ImageName, rec.MIMEType, dim)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sChoose entry to view (Enter = latest): %s", utils.Green, utils.Reset)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	selected := len(history.Analyses) - 1
	if choice != "" {
		idx, convErr := strconv.Atoi(choice)
		if convErr != nil || idx < 1 || idx > len(history.Analyses) {
			fmt.Printf("%sInvalid selection. Showing latest entry.%s\n", utils.Red, utils.Reset)
		} else {
			selected = idx - 1
		}
	}

	record := history.Analyses[selected]
	utils.ClearTerminal()
	displayImageHistoryRecord(record)

	fmt.Printf("\n%sOptions:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] Show selected entry as JSON%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Show full TXT report%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3] Delete image history JSON%s\n", utils.Red, utils.Reset)
	utils.PrintReturnOption("4")
	fmt.Printf("\n%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		pretty, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			fmt.Printf("%sFailed to render JSON entry: %v%s\n", utils.Red, err, utils.Reset)
		} else {
			fmt.Printf("\n%s%s%s\n", utils.Blue, string(pretty), utils.Reset)
		}
		utils.PauseForInput()
	case "2":
		showStoredImageReport(record.ReportFile)
		utils.PauseForInput()
	case "3":
		if err := os.Remove(imageHistoryFile); err != nil {
			fmt.Printf("%sFailed to delete history: %v%s\n", utils.Red, err, utils.Reset)
		} else {
			fmt.Printf("%s✓ Image history deleted successfully!%s\n", utils.Green, utils.Reset)
		}
		time.Sleep(2 * time.Second)
	case "4":
		return
	default:
		fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
		time.Sleep(2 * time.Second)
	}
}

func displayImageHistoryRecord(rec ImageAnalysisRecord) {
	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════════════╗%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s║                    IMAGE ANALYSIS DETAILS                         ║%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════════════╝%s\n", utils.Blue, utils.Reset)

	fmt.Printf("\n%sAnalyzed at:%s %s\n", utils.Green, utils.Reset, rec.AnalyzedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("%sImage:%s %s\n", utils.Green, utils.Reset, rec.ImagePath)
	fmt.Printf("%sSize:%s %s (%d bytes)\n", utils.Green, utils.Reset, rec.SizeHuman, rec.SizeBytes)
	fmt.Printf("%sMIME:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.MIMEType))
	fmt.Printf("%sDecoder format:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.DecoderFormat))

	if rec.Width > 0 && rec.Height > 0 {
		fmt.Printf("%sDimensions:%s %dx%d\n", utils.Green, utils.Reset, rec.Width, rec.Height)
	} else {
		fmt.Printf("%sDimensions:%s N/A\n", utils.Green, utils.Reset)
	}

	fmt.Printf("%sColor model:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.ColorModel))
	if rec.EntropyBitsPerByte != nil {
		fmt.Printf("%sEntropy:%s %.6f bits/byte\n", utils.Green, utils.Reset, *rec.EntropyBitsPerByte)
	} else {
		fmt.Printf("%sEntropy:%s N/A\n", utils.Green, utils.Reset)
	}
	if rec.GPSLatitude != nil && rec.GPSLongitude != nil {
		fmt.Printf("%sGPS:%s %.6f, %.6f (%s)\n", utils.Green, utils.Reset, *rec.GPSLatitude, *rec.GPSLongitude, fieldOrNA(rec.GPSCoordinatesSource))
	} else {
		fmt.Printf("%sGPS:%s N/A\n", utils.Green, utils.Reset)
	}
	if rec.GeoLookupAttempted {
		fmt.Printf("%sGeo provider:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.GeoLookupProvider))
		if strings.TrimSpace(rec.GeoLookupError) != "" {
			fmt.Printf("%sGeo lookup error:%s %s\n", utils.Yellow, utils.Reset, rec.GeoLookupError)
		} else {
			fmt.Printf("%sGeo location:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.GeoDisplayName))
			fmt.Printf("%sGeo map:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.GeoMapURL))
			fmt.Printf("%sGoogle Maps:%s %s\n", utils.Green, utils.Reset, fieldOrNA(rec.GeoGoogleMapsURL))
		}
	}

	fmt.Printf("%sMD5:%s %s\n", utils.Green, utils.Reset, rec.Hashes.MD5)
	fmt.Printf("%sSHA256:%s %s\n", utils.Green, utils.Reset, rec.Hashes.SHA256)
	fmt.Printf("%sExifTool installed:%s %t\n", utils.Green, utils.Reset, rec.ExifToolInstalled)
	if strings.TrimSpace(rec.ExifToolError) != "" {
		fmt.Printf("%sExifTool error:%s %s\n", utils.Yellow, utils.Reset, rec.ExifToolError)
	}
	if strings.TrimSpace(rec.ReportFile) != "" {
		fmt.Printf("%sTXT report:%s %s\n", utils.Green, utils.Reset, rec.ReportFile)
	}
}

func showStoredImageReport(reportFile string) {
	if strings.TrimSpace(reportFile) == "" {
		fmt.Printf("%sNo report path stored for this entry.%s\n", utils.Yellow, utils.Reset)
		return
	}

	raw, err := os.ReadFile(reportFile)
	if err != nil {
		fmt.Printf("%sCould not read report file: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	fmt.Printf("\n%s=== STORED TXT REPORT ===%s\n\n", utils.Blue, utils.Reset)
	fmt.Printf("%s%s%s\n", utils.Blue, string(raw), utils.Reset)
}

func promptImagePath(reader *bufio.Reader) (string, error) {
	fmt.Printf("%s[1] Insert full image path manually%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Open file picker%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3] Cancel%s\n\n", utils.Green, utils.Reset)
	fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)

	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	switch option {
	case "1":
		fmt.Printf("%sImage full path: %s", utils.Green, utils.Reset)
		inputPath, _ := reader.ReadString('\n')
		return normalizeAndValidatePath(inputPath)
	case "2":
		selectedPath, err := selectImageFileDialog()
		if err != nil {
			return "", err
		}
		return normalizeAndValidatePath(selectedPath)
	case "3":
		return "", nil
	default:
		return "", fmt.Errorf("invalid option")
	}
}

func normalizeAndValidatePath(inputPath string) (string, error) {
	cleanPath := strings.TrimSpace(inputPath)
	cleanPath = strings.Trim(cleanPath, `"`)
	cleanPath = strings.Trim(cleanPath, `'`)

	if cleanPath == "" {
		return "", fmt.Errorf("empty path")
	}

	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("cannot access file: %w", err)
	}

	if info.IsDir() {
		return "", fmt.Errorf("path points to a directory")
	}

	return absPath, nil
}

func selectImageFileDialog() (string, error) {
	switch utils.DetectOS() {
	case "windows":
		psScript := "$ErrorActionPreference='Stop';" +
			"Add-Type -AssemblyName System.Windows.Forms;" +
			"$f=New-Object System.Windows.Forms.OpenFileDialog;" +
			"$f.Filter='Image Files|*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.tif;*.tiff;*.webp;*.heic;*.avif|All Files|*.*';" +
			"if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){[Console]::Out.Write($f.FileName)}"
		out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
		if err != nil {
			return "", fmt.Errorf("failed to open file picker on Windows: %w", err)
		}
		if strings.TrimSpace(string(out)) == "" {
			return "", fmt.Errorf("no file selected")
		}
		return strings.TrimSpace(string(out)), nil

	case "darwin":
		out, err := exec.Command("osascript", "-e", `POSIX path of (choose file of type {"public.image"})`).Output()
		if err != nil {
			return "", fmt.Errorf("failed to open file picker on macOS: %w", err)
		}
		if strings.TrimSpace(string(out)) == "" {
			return "", fmt.Errorf("no file selected")
		}
		return strings.TrimSpace(string(out)), nil

	default:
		if _, err := exec.LookPath("zenity"); err == nil {
			out, zenErr := exec.Command(
				"zenity",
				"--file-selection",
				"--title=Select an image",
				"--file-filter=Images | *.jpg *.jpeg *.png *.gif *.bmp *.tif *.tiff *.webp *.heic *.avif",
				"--file-filter=All files | *",
			).Output()
			if zenErr == nil && strings.TrimSpace(string(out)) != "" {
				return strings.TrimSpace(string(out)), nil
			}
		}

		if _, err := exec.LookPath("kdialog"); err == nil {
			out, kErr := exec.Command(
				"kdialog",
				"--getopenfilename",
				"",
				"Images (*.jpg *.jpeg *.png *.gif *.bmp *.tif *.tiff *.webp *.heic *.avif)",
			).Output()
			if kErr == nil && strings.TrimSpace(string(out)) != "" {
				return strings.TrimSpace(string(out)), nil
			}
		}

		return "", fmt.Errorf("file picker not available (install zenity or kdialog), use manual full path")
	}
}

func analyzeImage(path string) (ImageAnalysisResult, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return ImageAnalysisResult{}, err
	}

	hashes, err := computeFileHashes(path)
	if err != nil {
		return ImageAnalysisResult{}, err
	}

	mimeType, magicHex, err := detectMimeAndMagic(path)
	if err != nil {
		return ImageAnalysisResult{}, err
	}

	cfg, format, cfgErr := decodeImageConfig(path)
	entropy, entropyErr := computeEntropy(path)
	exifResult := extractExifToolData(path)

	lat, lon, gpsSource, hasGPS := extractCoordinatesFromExif(exifResult.Structured)
	geoResult := ReverseGeoResult{}
	if hasGPS {
		geoResult = reverseGeocodeFromCoordinates(lat, lon)
	}

	record := ImageAnalysisRecord{
		AnalyzedAt:               time.Now(),
		ImagePath:                path,
		ImageName:                filepath.Base(path),
		Extension:                strings.ToLower(filepath.Ext(path)),
		SizeBytes:                fileInfo.Size(),
		SizeHuman:                humanSize(fileInfo.Size()),
		Permissions:              fileInfo.Mode().String(),
		ModifiedAt:               fileInfo.ModTime(),
		MIMEType:                 mimeType,
		MagicBytes:               magicHex,
		Hashes:                   hashes,
		ExifToolInstalled:        exifResult.Available,
		ExifToolInstallAttempted: exifResult.InstallAttempted,
		ExifToolInstallLog:       exifResult.InstallLog,
		ExifToolError:            exifResult.ErrorMessage,
		ExifMetadata:             exifResult.Structured,
		GeoLookupAttempted:       geoResult.Attempted,
		GeoLookupProvider:        geoResult.Provider,
		GeoLookupError:           geoResult.Error,
		GeoDisplayName:           geoResult.DisplayName,
		GeoCountry:               geoResult.Country,
		GeoRegion:                geoResult.Region,
		GeoCity:                  geoResult.City,
		GeoPostcode:              geoResult.Postcode,
		GeoMapURL:                geoResult.MapURL,
	}

	if cfgErr == nil {
		record.DecoderFormat = format
		record.Width = cfg.Width
		record.Height = cfg.Height
		record.ColorModel = fmt.Sprintf("%T", cfg.ColorModel)
	}
	if entropyErr == nil {
		entropyCopy := entropy
		record.EntropyBitsPerByte = &entropyCopy
	}
	if hasGPS {
		latCopy := lat
		lonCopy := lon
		record.GPSLatitude = &latCopy
		record.GPSLongitude = &lonCopy
		record.GPSCoordinatesSource = gpsSource
		record.GeoGoogleMapsURL = buildGoogleMapsURL(lat, lon)
	}

	report := buildImageReport(record, cfgErr, entropyErr, exifResult)
	return ImageAnalysisResult{Record: record, Report: report}, nil
}

func buildImageReport(record ImageAnalysisRecord, cfgErr error, entropyErr error, exifResult ExifToolResult) string {
	var sb strings.Builder

	sb.WriteString("============================================================\n")
	sb.WriteString("IMAGE FORENSIC REPORT\n")
	sb.WriteString("============================================================\n\n")

	sb.WriteString("[FILE]\n")
	sb.WriteString("Path: " + record.ImagePath + "\n")
	sb.WriteString("Filename: " + record.ImageName + "\n")
	sb.WriteString("Extension: " + record.Extension + "\n")
	sb.WriteString("Size (bytes): " + strconv.FormatInt(record.SizeBytes, 10) + "\n")
	sb.WriteString("Size (human): " + record.SizeHuman + "\n")
	sb.WriteString("Permissions: " + record.Permissions + "\n")
	sb.WriteString("Modified: " + record.ModifiedAt.Format(time.RFC3339) + "\n")
	sb.WriteString("Analyzed: " + record.AnalyzedAt.Format(time.RFC3339) + "\n")
	sb.WriteString("\n")

	sb.WriteString("[SIGNATURE]\n")
	sb.WriteString("MIME (magic): " + fieldOrNA(record.MIMEType) + "\n")
	sb.WriteString("Magic bytes (first 32): " + fieldOrNA(record.MagicBytes) + "\n")
	if cfgErr == nil {
		sb.WriteString("Image format (decoder): " + fieldOrNA(record.DecoderFormat) + "\n")
		sb.WriteString(fmt.Sprintf("Dimensions: %dx%d\n", record.Width, record.Height))
		sb.WriteString("Color model: " + fieldOrNA(record.ColorModel) + "\n")
	} else {
		sb.WriteString("Image decode/config: not available (" + cfgErr.Error() + ")\n")
	}
	if entropyErr == nil && record.EntropyBitsPerByte != nil {
		sb.WriteString(fmt.Sprintf("Shannon entropy: %.6f bits/byte\n", *record.EntropyBitsPerByte))
	} else {
		sb.WriteString("Shannon entropy: not available")
		if entropyErr != nil {
			sb.WriteString(" (" + entropyErr.Error() + ")")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	sb.WriteString("[GEOLOCATION]\n")
	if record.GPSLatitude != nil && record.GPSLongitude != nil {
		sb.WriteString(fmt.Sprintf("GPS coordinates: %.6f, %.6f\n", *record.GPSLatitude, *record.GPSLongitude))
		sb.WriteString("GPS source: " + fieldOrNA(record.GPSCoordinatesSource) + "\n")
	} else {
		sb.WriteString("GPS coordinates: not available\n")
	}
	sb.WriteString("Online lookup attempted: " + strconv.FormatBool(record.GeoLookupAttempted) + "\n")
	if record.GeoLookupAttempted {
		sb.WriteString("Provider: " + fieldOrNA(record.GeoLookupProvider) + "\n")
		if strings.TrimSpace(record.GeoLookupError) != "" {
			sb.WriteString("Lookup error: " + record.GeoLookupError + "\n")
		} else {
			sb.WriteString("Display name: " + fieldOrNA(record.GeoDisplayName) + "\n")
			sb.WriteString("Country: " + fieldOrNA(record.GeoCountry) + "\n")
			sb.WriteString("Region: " + fieldOrNA(record.GeoRegion) + "\n")
			sb.WriteString("City: " + fieldOrNA(record.GeoCity) + "\n")
			sb.WriteString("Postcode: " + fieldOrNA(record.GeoPostcode) + "\n")
			sb.WriteString("Map URL: " + fieldOrNA(record.GeoMapURL) + "\n")
			sb.WriteString("Google Maps URL: " + fieldOrNA(record.GeoGoogleMapsURL) + "\n")
		}
	}
	sb.WriteString("\n")

	sb.WriteString("[HASHES]\n")
	sb.WriteString("MD5: " + record.Hashes.MD5 + "\n")
	sb.WriteString("SHA1: " + record.Hashes.SHA1 + "\n")
	sb.WriteString("SHA256: " + record.Hashes.SHA256 + "\n")
	sb.WriteString("SHA512: " + record.Hashes.SHA512 + "\n\n")

	sb.WriteString("[EXIFTOOL - COMPLETE METADATA]\n")
	sb.WriteString("Installed: " + strconv.FormatBool(record.ExifToolInstalled) + "\n")
	sb.WriteString("Auto-install attempted: " + strconv.FormatBool(record.ExifToolInstallAttempted) + "\n")
	if strings.TrimSpace(record.ExifToolInstallLog) != "" {
		sb.WriteString("Install log: " + record.ExifToolInstallLog + "\n")
	}
	if strings.TrimSpace(record.ExifToolError) != "" {
		sb.WriteString("Error: " + record.ExifToolError + "\n")
	}
	if strings.TrimSpace(exifResult.StructuredPretty) != "" {
		sb.WriteString("\nJSON (structured):\n")
		sb.WriteString(exifResult.StructuredPretty)
		sb.WriteString("\n")
	}
	if strings.TrimSpace(exifResult.GroupedText) != "" {
		sb.WriteString("\nRaw text (grouped):\n")
		sb.WriteString(exifResult.GroupedText)
		sb.WriteString("\n")
	}

	return sb.String()
}

func computeFileHashes(path string) (FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileHashes{}, err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	hSHA512 := sha512.New()

	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256, hSHA512), f); err != nil {
		return FileHashes{}, err
	}

	return FileHashes{
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		SHA1:   hex.EncodeToString(hSHA1.Sum(nil)),
		SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
		SHA512: hex.EncodeToString(hSHA512.Sum(nil)),
	}, nil
}

func detectMimeAndMagic(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return "", "", err
	}
	buf = buf[:n]

	mimeType := http.DetectContentType(buf)
	showN := n
	if showN > 32 {
		showN = 32
	}

	return mimeType, strings.ToUpper(hex.EncodeToString(buf[:showN])), nil
}

func decodeImageConfig(path string) (image.Config, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return image.Config{}, "", err
	}
	defer f.Close()

	cfg, format, err := image.DecodeConfig(f)
	if err != nil {
		return image.Config{}, "", err
	}
	return cfg, format, nil
}

func computeEntropy(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	var entropy float64
	total := float64(len(data))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	return entropy, nil
}

func extractExifToolData(path string) ExifToolResult {
	result := ExifToolResult{}

	exifBinary, err := findExifToolBinary()
	if err != nil {
		result.InstallAttempted = true
		installLog, installErr := autoInstallExifTool()
		result.InstallLog = installLog
		if installErr != nil {
			result.ErrorMessage = "exiftool not found and automatic installation failed: " + installErr.Error()
			return result
		}

		exifBinary, err = findExifToolBinary()
		if err != nil {
			result.ErrorMessage = "automatic installation completed but exiftool is still not in PATH"
			return result
		}
	}

	result.Available = true

	jsonOut, err := exec.Command(exifBinary, "-j", "-n", "-a", "-G1", "-s", "-u", "-ee", "-api", "largefilesupport=1", path).CombinedOutput()
	if err != nil {
		result.ErrorMessage = "failed to run exiftool (JSON): " + err.Error()
		return result
	}

	parsed, parseErr := parseExifJSON(jsonOut)
	if parseErr != nil {
		result.ErrorMessage = "failed to parse exiftool JSON: " + parseErr.Error()
		result.StructuredPretty = string(jsonOut)
	} else {
		result.Structured = parsed
		result.StructuredPretty = prettyMapJSON(parsed)
	}

	textOut, textErr := exec.Command(exifBinary, "-a", "-u", "-g1", "-s", "-ee", "-api", "largefilesupport=1", path).CombinedOutput()
	if textErr != nil {
		if result.ErrorMessage == "" {
			result.ErrorMessage = "failed to run exiftool (grouped text): " + textErr.Error()
		}
		return result
	}

	result.GroupedText = string(textOut)
	return result
}

func findExifToolBinary() (string, error) {
	candidates := []string{"exiftool", "exiftool.exe"}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("exiftool not found in PATH")
}

func autoInstallExifTool() (string, error) {
	switch utils.DetectOS() {
	case "windows":
		return installExifToolWindows()
	case "linux":
		return installExifToolLinux()
	default:
		return "", fmt.Errorf("automatic installation is only configured for Windows and Linux")
	}
}

func installExifToolWindows() (string, error) {
	var logs []string

	if commandExists("winget") {
		if out, err := runCommand("winget", "install", "--id", "OliverBetz.ExifTool", "-e", "--accept-package-agreements", "--accept-source-agreements"); err == nil {
			return "winget install succeeded", nil
		} else {
			logs = append(logs, "winget: "+out+" | "+err.Error())
		}
	}

	if commandExists("choco") {
		if out, err := runCommand("choco", "install", "exiftool", "-y"); err == nil {
			return "choco install succeeded", nil
		} else {
			logs = append(logs, "choco: "+out+" | "+err.Error())
		}
	}

	if commandExists("scoop") {
		if out, err := runCommand("scoop", "install", "exiftool"); err == nil {
			return "scoop install succeeded", nil
		} else {
			logs = append(logs, "scoop: "+out+" | "+err.Error())
		}
	}

	if len(logs) == 0 {
		return "", fmt.Errorf("no supported package manager found (winget/choco/scoop)")
	}
	return strings.Join(logs, " || "), fmt.Errorf("all Windows installation methods failed")
}

func installExifToolLinux() (string, error) {
	var logs []string

	if commandExists("apt-get") {
		_, _ = runCommandWithFallbackSudo("apt-get", "update", "-y")
		if out, err := runCommandWithFallbackSudo("apt-get", "install", "-y", "libimage-exiftool-perl"); err == nil {
			return "apt-get install succeeded", nil
		} else {
			logs = append(logs, "apt-get: "+out+" | "+err.Error())
		}
	}

	if commandExists("dnf") {
		if out, err := runCommandWithFallbackSudo("dnf", "install", "-y", "perl-Image-ExifTool"); err == nil {
			return "dnf install succeeded", nil
		} else {
			logs = append(logs, "dnf: "+out+" | "+err.Error())
		}
	}

	if commandExists("yum") {
		if out, err := runCommandWithFallbackSudo("yum", "install", "-y", "perl-Image-ExifTool"); err == nil {
			return "yum install succeeded", nil
		} else {
			logs = append(logs, "yum: "+out+" | "+err.Error())
		}
	}

	if commandExists("pacman") {
		if out, err := runCommandWithFallbackSudo("pacman", "-Sy", "--noconfirm", "perl-image-exiftool"); err == nil {
			return "pacman install succeeded", nil
		} else {
			logs = append(logs, "pacman: "+out+" | "+err.Error())
		}
	}

	if commandExists("zypper") {
		if out, err := runCommandWithFallbackSudo("zypper", "--non-interactive", "install", "exiftool"); err == nil {
			return "zypper install succeeded", nil
		} else {
			logs = append(logs, "zypper: "+out+" | "+err.Error())
		}
	}

	if len(logs) == 0 {
		return "", fmt.Errorf("no supported package manager found (apt/dnf/yum/pacman/zypper)")
	}
	return strings.Join(logs, " || "), fmt.Errorf("all Linux installation methods failed")
}

func runCommandWithFallbackSudo(name string, args ...string) (string, error) {
	out, err := runCommand(name, args...)
	if err == nil {
		return out, nil
	}

	if !commandExists("sudo") {
		return out, err
	}

	sudoArgs := append([]string{name}, args...)
	return runCommand("sudo", sudoArgs...)
}

func runCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	cleanOut := strings.TrimSpace(string(out))
	if len(cleanOut) > 350 {
		cleanOut = cleanOut[:350] + "...(truncated)"
	}
	if err != nil {
		if cleanOut == "" {
			return "", err
		}
		return cleanOut, err
	}
	return cleanOut, nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func parseExifJSON(raw []byte) (map[string]interface{}, error) {
	var parsed []map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	if len(parsed) == 0 {
		return map[string]interface{}{}, nil
	}
	return parsed[0], nil
}

func prettyMapJSON(data map[string]interface{}) string {
	if len(data) == 0 {
		return "{}"
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make(map[string]interface{}, len(data))
	for _, k := range keys {
		ordered[k] = data[k]
	}

	pretty, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(pretty)
}

func extractCoordinatesFromExif(meta map[string]interface{}) (float64, float64, string, bool) {
	if len(meta) == 0 {
		return 0, 0, "", false
	}

	pairKeys := []string{
		"Composite:GPSPosition",
		"QuickTime:GPSCoordinates",
		"XMP:GPSCoordinates",
	}
	for _, key := range pairKeys {
		raw, ok := meta[key]
		if !ok {
			continue
		}
		if strVal, ok := raw.(string); ok {
			if lat, lon, ok := parseCoordinatePair(strVal); ok {
				return lat, lon, key, true
			}
		}
	}

	latKeys := []string{
		"EXIF:GPSLatitude",
		"Composite:GPSLatitude",
		"XMP:GPSLatitude",
		"QuickTime:GPSLatitude",
	}
	lonKeys := []string{
		"EXIF:GPSLongitude",
		"Composite:GPSLongitude",
		"XMP:GPSLongitude",
		"QuickTime:GPSLongitude",
	}
	latRefKeys := []string{
		"EXIF:GPSLatitudeRef",
		"Composite:GPSLatitudeRef",
		"XMP:GPSLatitudeRef",
	}
	lonRefKeys := []string{
		"EXIF:GPSLongitudeRef",
		"Composite:GPSLongitudeRef",
		"XMP:GPSLongitudeRef",
	}

	lat, latSource, latOK := findCoordinateValue(meta, latKeys, true)
	lon, lonSource, lonOK := findCoordinateValue(meta, lonKeys, false)
	if !latOK || !lonOK {
		return 0, 0, "", false
	}

	lat = applyCoordinateReference(lat, meta, latRefKeys, true)
	lon = applyCoordinateReference(lon, meta, lonRefKeys, false)

	if !isValidCoordinate(lat, true) || !isValidCoordinate(lon, false) {
		return 0, 0, "", false
	}

	return lat, lon, latSource + " + " + lonSource, true
}

func findCoordinateValue(meta map[string]interface{}, keys []string, isLat bool) (float64, string, bool) {
	for _, key := range keys {
		value, ok := meta[key]
		if !ok {
			continue
		}
		parsed, ok := parseCoordinateValue(value, isLat)
		if ok {
			return parsed, key, true
		}
	}
	return 0, "", false
}

func parseCoordinateValue(value interface{}, isLat bool) (float64, bool) {
	switch v := value.(type) {
	case float64:
		if isValidCoordinate(v, isLat) {
			return v, true
		}
	case float32:
		val := float64(v)
		if isValidCoordinate(val, isLat) {
			return val, true
		}
	case int:
		val := float64(v)
		if isValidCoordinate(val, isLat) {
			return val, true
		}
	case int64:
		val := float64(v)
		if isValidCoordinate(val, isLat) {
			return val, true
		}
	case json.Number:
		val, err := v.Float64()
		if err == nil && isValidCoordinate(val, isLat) {
			return val, true
		}
	case string:
		return parseCoordinateString(v, isLat)
	}
	return 0, false
}

func parseCoordinateString(raw string, isLat bool) (float64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}

	normalized := strings.ReplaceAll(trimmed, ",", ".")
	if dec, err := strconv.ParseFloat(normalized, 64); err == nil {
		if isValidCoordinate(dec, isLat) {
			return dec, true
		}
	}

	numberRe := regexp.MustCompile(`[-+]?\d+(?:[.,]\d+)?`)
	numMatches := numberRe.FindAllString(trimmed, -1)
	if len(numMatches) == 0 {
		return 0, false
	}

	values := make([]float64, 0, len(numMatches))
	for _, m := range numMatches {
		f, err := strconv.ParseFloat(strings.ReplaceAll(m, ",", "."), 64)
		if err != nil {
			return 0, false
		}
		values = append(values, f)
	}

	decimal := math.Abs(values[0])
	if len(values) >= 2 {
		decimal += math.Abs(values[1]) / 60.0
	}
	if len(values) >= 3 {
		decimal += math.Abs(values[2]) / 3600.0
	}

	if values[0] < 0 {
		decimal = -decimal
	}

	upper := strings.ToUpper(trimmed)
	if strings.Contains(upper, "S") || strings.Contains(upper, "W") {
		decimal = -math.Abs(decimal)
	}
	if strings.Contains(upper, "N") || strings.Contains(upper, "E") {
		decimal = math.Abs(decimal)
	}

	if !isValidCoordinate(decimal, isLat) {
		return 0, false
	}
	return decimal, true
}

func parseCoordinatePair(raw string) (float64, float64, bool) {
	normalized := strings.ReplaceAll(raw, ";", " ")
	normalized = strings.ReplaceAll(normalized, ",", " ")
	parts := strings.Fields(normalized)
	if len(parts) >= 2 {
		lat, latOK := parseCoordinateString(parts[0], true)
		lon, lonOK := parseCoordinateString(parts[1], false)
		if latOK && lonOK {
			return lat, lon, true
		}
	}

	decimalPairRe := regexp.MustCompile(`[-+]?\d+(?:[.,]\d+)?`)
	numMatches := decimalPairRe.FindAllString(raw, -1)
	if len(numMatches) >= 2 {
		lat, latErr := strconv.ParseFloat(strings.ReplaceAll(numMatches[0], ",", "."), 64)
		lon, lonErr := strconv.ParseFloat(strings.ReplaceAll(numMatches[1], ",", "."), 64)
		if latErr == nil && lonErr == nil && isValidCoordinate(lat, true) && isValidCoordinate(lon, false) {
			return lat, lon, true
		}
	}

	return 0, 0, false
}

func applyCoordinateReference(value float64, meta map[string]interface{}, refKeys []string, isLat bool) float64 {
	for _, key := range refKeys {
		raw, ok := meta[key]
		if !ok {
			continue
		}

		ref := strings.ToUpper(strings.TrimSpace(fmt.Sprint(raw)))
		if ref == "" {
			continue
		}

		if isLat {
			if strings.HasPrefix(ref, "S") {
				return -math.Abs(value)
			}
			if strings.HasPrefix(ref, "N") {
				return math.Abs(value)
			}
		} else {
			if strings.HasPrefix(ref, "W") {
				return -math.Abs(value)
			}
			if strings.HasPrefix(ref, "E") {
				return math.Abs(value)
			}
		}
	}
	return value
}

func isValidCoordinate(value float64, isLat bool) bool {
	if isLat {
		return value >= -90 && value <= 90
	}
	return value >= -180 && value <= 180
}

func reverseGeocodeFromCoordinates(lat, lon float64) ReverseGeoResult {
	result := ReverseGeoResult{
		Attempted: true,
		Provider:  "OpenStreetMap Nominatim",
		MapURL:    fmt.Sprintf("https://www.openstreetmap.org/?mlat=%.6f&mlon=%.6f#map=16/%.6f/%.6f", lat, lon, lat, lon),
	}

	query := url.Values{}
	query.Set("format", "jsonv2")
	query.Set("lat", fmt.Sprintf("%.7f", lat))
	query.Set("lon", fmt.Sprintf("%.7f", lon))
	query.Set("zoom", "18")
	query.Set("addressdetails", "1")

	endpoint := "https://nominatim.openstreetmap.org/reverse?" + query.Encode()
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	req.Header.Set("User-Agent", "G0-MULTITOOL/1.0 image-analyser")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if resp.StatusCode != http.StatusOK {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 180 {
			snippet = snippet[:180] + "...(truncated)"
		}
		result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, snippet)
		return result
	}

	var payload struct {
		DisplayName string            `json:"display_name"`
		Address     map[string]string `json:"address"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		result.Error = err.Error()
		return result
	}

	result.DisplayName = payload.DisplayName
	if payload.Address != nil {
		result.Country = firstNonEmpty(
			payload.Address["country"],
			payload.Address["country_name"],
		)
		result.Region = firstNonEmpty(
			payload.Address["state"],
			payload.Address["region"],
			payload.Address["county"],
		)
		result.City = firstNonEmpty(
			payload.Address["city"],
			payload.Address["town"],
			payload.Address["village"],
			payload.Address["municipality"],
			payload.Address["hamlet"],
			payload.Address["suburb"],
		)
		result.Postcode = payload.Address["postcode"]
	}

	return result
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func promptOpenMapAfterScan(reader *bufio.Reader, rec ImageAnalysisRecord) {
	if rec.GPSLatitude == nil || rec.GPSLongitude == nil {
		return
	}

	lat := *rec.GPSLatitude
	lon := *rec.GPSLongitude
	googleURL := buildGoogleMapsURL(lat, lon)
	osmURL := rec.GeoMapURL
	if strings.TrimSpace(osmURL) == "" {
		osmURL = fmt.Sprintf("https://www.openstreetmap.org/?mlat=%.6f&mlon=%.6f#map=16/%.6f/%.6f", lat, lon, lat, lon)
	}

	fmt.Printf("\n%s[?] GPS coordinates found (%.6f, %.6f)%s\n", utils.Yellow, lat, lon, utils.Reset)
	if strings.TrimSpace(rec.GeoDisplayName) != "" {
		fmt.Printf("%s    Location:%s %s\n", utils.Green, utils.Reset, rec.GeoDisplayName)
	}
	fmt.Printf("%s[1] Open Google Maps%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Open OpenStreetMap%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3] Do not open map%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%sChoose option (Enter = 1): %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		input = "1"
	}

	var targetURL string
	switch input {
	case "1":
		targetURL = googleURL
	case "2":
		targetURL = osmURL
	case "3":
		return
	default:
		fmt.Printf("%sInvalid option. Skipping map open.%s\n", utils.Red, utils.Reset)
		return
	}

	if err := openURLInDefaultApp(targetURL); err != nil {
		fmt.Printf("%s[!] Could not open map automatically: %v%s\n", utils.Yellow, err, utils.Reset)
		fmt.Printf("%sURL:%s %s\n", utils.Green, utils.Reset, targetURL)
		return
	}

	fmt.Printf("%s[✓] Opened map in default app/browser.%s\n", utils.Green, utils.Reset)
}

func buildGoogleMapsURL(lat, lon float64) string {
	return fmt.Sprintf("https://www.google.com/maps?q=%.7f,%.7f", lat, lon)
}

func openURLInDefaultApp(targetURL string) error {
	switch utils.DetectOS() {
	case "windows":
		return exec.Command("cmd", "/c", "start", "", targetURL).Start()
	case "darwin":
		return exec.Command("open", targetURL).Start()
	default:
		if commandExists("xdg-open") {
			return exec.Command("xdg-open", targetURL).Start()
		}
		if commandExists("gio") {
			return exec.Command("gio", "open", targetURL).Start()
		}
		return fmt.Errorf("no URL opener found (xdg-open/gio)")
	}
}

func saveImageHistoryRecord(record ImageAnalysisRecord) error {
	history := ImageAnalysisHistory{}

	raw, err := os.ReadFile(imageHistoryFile)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &history); err != nil {
			return err
		}
	}

	history.Analyses = append(history.Analyses, record)
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(imageHistoryFile, data, 0644)
}

func loadImageHistory() (*ImageAnalysisHistory, error) {
	data, err := os.ReadFile(imageHistoryFile)
	if err != nil {
		return nil, err
	}

	var history ImageAnalysisHistory
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, err
	}

	return &history, nil
}

func saveImageReport(imagePath, report string) (string, error) {
	if err := os.MkdirAll(imageReportsDir, 0755); err != nil {
		return "", err
	}

	base := strings.TrimSuffix(filepath.Base(imagePath), filepath.Ext(imagePath))
	timestamp := time.Now().Format("20060102_150405")
	outPath := filepath.Join(imageReportsDir, fmt.Sprintf("%s_%s_report.txt", base, timestamp))

	if err := os.WriteFile(outPath, []byte(report), 0644); err != nil {
		return "", err
	}

	abs, err := filepath.Abs(outPath)
	if err != nil {
		return outPath, nil
	}
	return abs, nil
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func fieldOrNA(v string) string {
	if strings.TrimSpace(v) == "" {
		return "N/A"
	}
	return v
}

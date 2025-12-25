// Source: github.com/corazawaf/coraza/v3 - internal/bodyprocessors/multipart.go
// This is the multipart parser used by Coraza WAF

package bodyprocessors

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"strings"
)

type multipartBodyProcessor struct{}

func (mbp *multipartBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	mimeType := options.Mime
	storagePath := options.StoragePath
	
	// IMPORTANT: Uses Go's mime.ParseMediaType to parse Content-Type
	// This is stricter than some other parsers
	mediaType, params, err := mime.ParseMediaType(mimeType)
	if err != nil {
		return err
	}
	
	if !strings.HasPrefix(mediaType, "multipart/") {
		return errors.New("not a multipart body")
	}
	
	// Creates multipart reader with boundary from params
	// Note: Go's mime.ParseMediaType handles duplicate params differently than Node.js
	mr := multipart.NewReader(reader, params["boundary"])
	
	totalSize := int64(0)
	filesCol := v.Files()
	filesTmpNamesCol := v.FilesTmpNames()
	fileSizesCol := v.FilesSizes()
	postCol := v.ArgsPost()
	filesCombinedSizeCol := v.FilesCombinedSize()
	filesNamesCol := v.FilesNames()
	headersNames := v.MultipartPartHeaders()
	
	for {
		// NextPart reads each part of the multipart body
		// Stops when it encounters the closing boundary --boundary--
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		partName := p.FormName()
		
		// Store part headers for inspection by rules
		for key, values := range p.Header {
			for _, value := range values {
				headersNames.Add(partName, fmt.Sprintf("%s: %s", key, value))
			}
		}
		
		// Check if this is a file upload
		filename := originFileName(p)
		if filename != "" {
			// File handling...
			var size int64
			if environment.HasAccessToFS {
				temp, err := os.CreateTemp(storagePath, "crzmp*")
				if err != nil {
					return err
				}
				sz, err := io.Copy(temp, p)
				if err != nil {
					return err
				}
				size = sz
				filesTmpNamesCol.Add("", temp.Name())
			} else {
				sz, err := io.Copy(io.Discard, p)
				if err != nil {
					return err
				}
				size = sz
			}
			totalSize += size
			filesCol.Add("", filename)
			fileSizesCol.SetIndex(filename, 0, fmt.Sprintf("%d", size))
			filesNamesCol.Add("", p.FormName())
		} else {
			// Regular field - read value as raw bytes
			// NOTE: No charset decoding is performed here!
			// The value is stored as-is, which means UTF-16 encoded
			// content will have null bytes interspersed
			data, err := io.ReadAll(p)
			if err != nil {
				return err
			}
			totalSize += int64(len(data))
			postCol.Add(p.FormName(), string(data))
		}
		filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
	}
	return nil
}

// originFileName returns the filename from Content-Disposition header
func originFileName(p *multipart.Part) string {
	v := p.Header.Get("Content-Disposition")
	_, dispositionParams, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}
	return dispositionParams["filename"]
}


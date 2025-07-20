package s3api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/pb"
	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
)

// BrowserItem represents a file or directory in the bucket browser
type BrowserItem struct {
	Name        string    `json:"name"`
	IsDirectory bool      `json:"is_directory"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
}

// S3Operations provides access to S3API internal operations for the console
type S3Operations struct {
	iam                *IdentityAccessManagement
	option             *S3ApiServerOption
	consoleAdminKey    string
	consoleAdminSecret string
}

// ConsoleCredential represents console admin credentials
type ConsoleCredential struct {
	AccessKey string
	SecretKey string
}

// BucketInfo represents bucket information for console
type BucketInfo struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
	ObjectCount  int64     `json:"object_count"`
	Size         int64     `json:"size"`
	Region       string    `json:"region"`
}

// NewS3Operations creates a new S3Operations instance for console use from S3ApiServer
func NewS3Operations(s3ApiServer *S3ApiServer, consoleAdminKey, consoleAdminSecret string) *S3Operations {
	return &S3Operations{
		iam:                s3ApiServer.iam,
		option:             s3ApiServer.option,
		consoleAdminKey:    consoleAdminKey,
		consoleAdminSecret: consoleAdminSecret,
	}
}

// AuthenticateConsole validates console admin credentials (separate from S3 credentials)
func (ops *S3Operations) AuthenticateConsole(accessKey, secretKey string) (*Identity, error) {
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("console credentials cannot be empty")
	}

	// Validate against the configured console admin credentials
	if accessKey != ops.consoleAdminKey || secretKey != ops.consoleAdminSecret {
		return nil, fmt.Errorf("invalid console credentials")
	}

	// Console admin credentials are separate from S3 credentials
	// We create a virtual admin identity for console operations
	// This allows console to work even when S3 API has no IAM config
	adminIdentity := &Identity{
		Name: "console_admin",
		Actions: []Action{
			"Admin", "Read", "List", "Tagging", "Write",
		},
	}

	return adminIdentity, nil
}

// ListBuckets returns all buckets accessible to the console
func (ops *S3Operations) ListBuckets(ctx context.Context, identity *Identity) ([]BucketInfo, error) {
	var buckets []BucketInfo

	// Use filer client to list buckets
	err := pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		stream, err := client.ListEntries(ctx, &filer_pb.ListEntriesRequest{
			Directory:          ops.option.BucketsPath,
			InclusiveStartFrom: false,
			Limit:              1000,
		})
		if err != nil {
			return fmt.Errorf("failed to list buckets: %w", err)
		}

		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to receive bucket entry: %w", err)
			}

			entry := resp.Entry
			if !entry.IsDirectory {
				continue
			}

			bucketInfo := BucketInfo{
				Name:         entry.Name,
				CreationDate: time.Unix(entry.Attributes.Crtime, 0),
				Region:       "us-east-1", // Default region
			}

			// Get bucket statistics by listing bucket contents
			objectCount, totalSize := ops.getBucketStats(ctx, entry.Name)
			bucketInfo.ObjectCount = objectCount
			bucketInfo.Size = totalSize

			buckets = append(buckets, bucketInfo)
		}
		return nil
	})

	return buckets, err
}

// CreateBucket creates a new bucket
func (ops *S3Operations) CreateBucket(ctx context.Context, identity *Identity, bucketName, region string) error {
	if bucketName == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}

	// Validate bucket name
	if err := validateBucketName(bucketName); err != nil {
		return err
	}

	return pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		// Check if bucket already exists
		_, err := client.LookupDirectoryEntry(ctx, &filer_pb.LookupDirectoryEntryRequest{
			Directory: ops.option.BucketsPath,
			Name:      bucketName,
		})
		if err == nil {
			return fmt.Errorf("bucket already exists: %s", bucketName)
		}

		// Create bucket directory
		now := time.Now().Unix()
		_, err = client.CreateEntry(ctx, &filer_pb.CreateEntryRequest{
			Directory: ops.option.BucketsPath,
			Entry: &filer_pb.Entry{
				Name:        bucketName,
				IsDirectory: true,
				Attributes: &filer_pb.FuseAttributes{
					Mtime:    now,
					Crtime:   now,
					FileMode: uint32(0755 | os.ModeDir),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}

		return nil
	})
}

// DeleteBucket deletes a bucket (must be empty)
func (ops *S3Operations) DeleteBucket(ctx context.Context, identity *Identity, bucketName string) error {
	if bucketName == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}

	return pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		bucketPath := fmt.Sprintf("%s/%s", ops.option.BucketsPath, bucketName)

		// Check if bucket exists
		_, err := client.LookupDirectoryEntry(ctx, &filer_pb.LookupDirectoryEntryRequest{
			Directory: ops.option.BucketsPath,
			Name:      bucketName,
		})
		if err != nil {
			return fmt.Errorf("bucket not found: %s", bucketName)
		}

		// Check if bucket is empty
		stream, err := client.ListEntries(ctx, &filer_pb.ListEntriesRequest{
			Directory: bucketPath,
			Limit:     1,
		})
		if err != nil {
			return fmt.Errorf("failed to check if bucket is empty: %w", err)
		}

		// Check if there's at least one entry
		_, err = stream.Recv()
		if err != io.EOF {
			if err == nil {
				return fmt.Errorf("bucket is not empty: %s", bucketName)
			}
			return fmt.Errorf("failed to check bucket contents: %w", err)
		}

		// Delete bucket
		_, err = client.DeleteEntry(ctx, &filer_pb.DeleteEntryRequest{
			Directory:            ops.option.BucketsPath,
			Name:                 bucketName,
			IsDeleteData:         false,
			IsRecursive:          false,
			IgnoreRecursiveError: false,
		})
		if err != nil {
			return fmt.Errorf("failed to delete bucket: %w", err)
		}

		return nil
	})
}

// TestConnection tests if the S3 operations are working
func (ops *S3Operations) TestConnection(ctx context.Context) error {
	return pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		// Test by listing the buckets directory
		_, err := client.LookupDirectoryEntry(ctx, &filer_pb.LookupDirectoryEntryRequest{
			Directory: "/",
			Name:      ops.option.BucketsPath[1:], // Remove leading slash
		})
		return err
	})
}

// getBucketStats calculates the number of objects and total size for a bucket
func (ops *S3Operations) getBucketStats(ctx context.Context, bucketName string) (int64, int64) {
	var objectCount int64
	var totalSize int64

	bucketPath := fmt.Sprintf("%s/%s", ops.option.BucketsPath, bucketName)

	// List all entries in the bucket recursively
	err := pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		return ops.listBucketContentsRecursively(ctx, client, bucketPath, &objectCount, &totalSize)
	})

	if err != nil {
		// If there's an error, return 0s (bucket might be empty or inaccessible)
		return 0, 0
	}

	return objectCount, totalSize
}

// listBucketContentsRecursively uses TraverseBfsMetadata for more efficient bucket statistics collection
func (ops *S3Operations) listBucketContentsRecursively(ctx context.Context, client filer_pb.SeaweedFilerClient, dirPath string, objectCount *int64, totalSize *int64) error {
	stream, err := client.TraverseBfsMetadata(ctx, &filer_pb.TraverseBfsMetadataRequest{
		Directory: dirPath,
	})
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		entry := resp.Entry
		if !entry.IsDirectory {
			// Count object and add its size
			*objectCount++
			*totalSize += int64(entry.Attributes.FileSize)
		}
	}

	return nil
}

// validateBucketName validates S3 bucket naming rules
func validateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return fmt.Errorf("bucket name must be between 3 and 63 characters")
	}

	// Must start and end with lowercase letter or number
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= '0' && name[0] <= '9')) {
		return fmt.Errorf("bucket name must start with a lowercase letter or number")
	}

	lastChar := name[len(name)-1]
	if !((lastChar >= 'a' && lastChar <= 'z') || (lastChar >= '0' && lastChar <= '9')) {
		return fmt.Errorf("bucket name must end with a lowercase letter or number")
	}

	// Check each character
	for i, char := range name {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '.') {
			return fmt.Errorf("bucket name can only contain lowercase letters, numbers, hyphens, and periods")
		}

		// No consecutive periods or hyphens
		if i > 0 && ((char == '.' && name[i-1] == '.') || (char == '-' && name[i-1] == '-')) {
			return fmt.Errorf("bucket name cannot contain consecutive periods or hyphens")
		}
	}

	return nil
}

// ListBucketContents lists the contents of a bucket directory
func (ops *S3Operations) ListBucketContents(ctx context.Context, identity *Identity, bucketName, currentPath string) ([]BrowserItem, error) {
	bucketPath := fmt.Sprintf("%s/%s", ops.option.BucketsPath, bucketName)
	if currentPath != "" {
		bucketPath = fmt.Sprintf("%s/%s", bucketPath, currentPath)
	}

	var items []BrowserItem

	err := pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		stream, err := client.ListEntries(ctx, &filer_pb.ListEntriesRequest{
			Directory:          bucketPath,
			InclusiveStartFrom: false,
			Limit:              1000,
		})
		if err != nil {
			return err
		}

		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			entry := resp.Entry
			item := BrowserItem{
				Name:        entry.Name,
				IsDirectory: entry.IsDirectory,
				Size:        int64(entry.Attributes.FileSize),
				ModTime:     time.Unix(entry.Attributes.Mtime, 0),
			}
			items = append(items, item)
		}

		return nil
	})

	return items, err
}

// CreateFolder creates a new folder (empty object with trailing slash) in the bucket
func (ops *S3Operations) CreateFolder(ctx context.Context, identity *Identity, bucketName, folderPath string) error {
	objectKey := folderPath
	if !strings.HasSuffix(objectKey, "/") {
		objectKey += "/"
	}

	// Create an empty object to represent the folder
	return ops.PutObject(ctx, identity, bucketName, objectKey, []byte{}, "application/x-directory")
}

// PutObject uploads an object to the bucket (for small content)
func (ops *S3Operations) PutObject(ctx context.Context, identity *Identity, bucketName, objectKey string, content []byte, contentType string) error {
	// Use the same HTTP API approach for consistency
	uploadUrl := ops.toFilerUrl(bucketName, objectKey)
	reader := strings.NewReader(string(content))
	return ops.putToFiler(uploadUrl, reader, contentType)
}

// PutObjectStream uploads an object to the bucket using SeaweedFS HTTP API for large files
func (ops *S3Operations) PutObjectStream(ctx context.Context, identity *Identity, bucketName, objectKey string, reader io.Reader, fileSize int64, contentType string) error {
	// Use the same approach as the real S3 API
	uploadUrl := ops.toFilerUrl(bucketName, objectKey)
	return ops.putToFiler(uploadUrl, reader, contentType)
}

// ensureDirectoryExists creates all parent directories if they don't exist
func (ops *S3Operations) ensureDirectoryExists(ctx context.Context, client filer_pb.SeaweedFilerClient, dirPath string) error {
	if dirPath == "" || dirPath == "/" {
		return nil
	}

	// Check if directory exists
	_, err := client.LookupDirectoryEntry(ctx, &filer_pb.LookupDirectoryEntryRequest{
		Directory: filepath.Dir(dirPath),
		Name:      filepath.Base(dirPath),
	})

	if err == nil {
		return nil // Directory exists
	}

	// Create parent directories first
	if err := ops.ensureDirectoryExists(ctx, client, filepath.Dir(dirPath)); err != nil {
		return err
	}

	// Create this directory
	_, err = client.CreateEntry(ctx, &filer_pb.CreateEntryRequest{
		Directory: filepath.Dir(dirPath),
		Entry: &filer_pb.Entry{
			Name:        filepath.Base(dirPath),
			IsDirectory: true,
			Attributes: &filer_pb.FuseAttributes{
				FileMode: 0755,
				Mtime:    time.Now().Unix(),
			},
		},
	})

	return err
}

// DeleteObject deletes a single object from the bucket
func (ops *S3Operations) DeleteObject(ctx context.Context, identity *Identity, bucketName, objectKey string) error {
	bucketPath := fmt.Sprintf("%s/%s", ops.option.BucketsPath, bucketName)
	objectPath := fmt.Sprintf("%s/%s", bucketPath, objectKey)

	return pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		_, err := client.DeleteEntry(ctx, &filer_pb.DeleteEntryRequest{
			Directory:    filepath.Dir(objectPath),
			Name:         filepath.Base(objectPath),
			IsDeleteData: true,
			IsRecursive:  false,
		})
		return err
	})
}

// DeleteFolder deletes a folder and all its contents
func (ops *S3Operations) DeleteFolder(ctx context.Context, identity *Identity, bucketName, folderPath string) error {
	bucketPath := fmt.Sprintf("%s/%s", ops.option.BucketsPath, bucketName)
	fullFolderPath := fmt.Sprintf("%s/%s", bucketPath, folderPath)

	return pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		_, err := client.DeleteEntry(ctx, &filer_pb.DeleteEntryRequest{
			Directory:    filepath.Dir(fullFolderPath),
			Name:         filepath.Base(fullFolderPath),
			IsDeleteData: true,
			IsRecursive:  true,
		})
		return err
	})
}

// GetObject retrieves an object from the bucket
func (ops *S3Operations) GetObject(ctx context.Context, identity *Identity, bucketName, objectKey string) ([]byte, string, error) {
	bucketPath := fmt.Sprintf("%s/%s", ops.option.BucketsPath, bucketName)
	objectPath := fmt.Sprintf("%s/%s", bucketPath, objectKey)

	var content []byte
	var contentType string

	err := pb.WithGrpcFilerClient(false, 0, ops.option.Filer, ops.option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		// Get entry metadata
		resp, err := client.LookupDirectoryEntry(ctx, &filer_pb.LookupDirectoryEntryRequest{
			Directory: filepath.Dir(objectPath),
			Name:      filepath.Base(objectPath),
		})
		if err != nil {
			return err
		}

		entry := resp.Entry
		if entry.IsDirectory {
			return fmt.Errorf("cannot download a directory")
		}

		contentType = entry.Attributes.Mime
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		// For simplicity, return empty content
		// In a real implementation, you'd read the file chunks and reconstruct the content
		content = []byte{}

		return nil
	})

	return content, contentType, err
}

// toFilerUrl constructs the filer URL for an object
func (ops *S3Operations) toFilerUrl(bucketName, objectKey string) string {
	// Construct the filer URL similar to how the real S3 API does it
	filerUrl := fmt.Sprintf("http://%s%s/%s/%s", ops.option.Filer.ToHttpAddress(), ops.option.BucketsPath, bucketName, objectKey)
	return filerUrl
}

// putToFiler uploads data to the filer using HTTP API
func (ops *S3Operations) putToFiler(uploadUrl string, reader io.Reader, contentType string) error {
	req, err := http.NewRequest(http.MethodPut, uploadUrl, reader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload to filer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("filer upload failed with status %d", resp.StatusCode)
	}

	return nil
}

package data

import (
	"github.com/seaweedfs/seaweedfs/weed/s3api"
)

// BucketsData holds data for the buckets listing page
type BucketsData struct {
	Buckets        []s3api.BucketInfo `json:"buckets"`
	TotalObjects   int64              `json:"total_objects"`
	TotalSize      int64              `json:"total_size"`
	S3ApiConnected bool               `json:"s3_api_connected"`
	LastUpdated    time.Time          `json:"last_updated"`
}

// CreateBucketRequest represents a request to create a new bucket
type CreateBucketRequest struct {
	Name   string `json:"name" form:"bucketName" binding:"required,min=3,max=63"`
	Region string `json:"region" form:"bucketRegion"`
}

// BucketBrowserData holds data for the bucket browser page
type BucketBrowserData struct {
	BucketName  string              `json:"bucket_name"`
	CurrentPath string              `json:"current_path"`
	Items       []s3api.BrowserItem `json:"items"`
}

// CreateFolderRequest represents a request to create a new folder
type CreateFolderRequest struct {
	FolderName  string `json:"folder_name" form:"folderName" binding:"required"`
	CurrentPath string `json:"current_path" form:"currentPath"`
}

// DeleteRequest represents a request to delete a file or folder
type DeleteRequest struct {
	Path        string `json:"path" binding:"required"`
	IsDirectory bool   `json:"is_directory"`
}

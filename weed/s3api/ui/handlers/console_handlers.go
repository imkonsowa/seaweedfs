package handlers

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/seaweedfs/seaweedfs/weed/s3api"
	"github.com/seaweedfs/seaweedfs/weed/s3api/ui/view/app"
	"github.com/seaweedfs/seaweedfs/weed/s3api/ui/view/data"
	"github.com/seaweedfs/seaweedfs/weed/s3api/ui/view/layout"
)

// ConsoleHandlers handles HTTP requests for the S3 Console
type ConsoleHandlers struct {
	s3Ops     *s3api.S3Operations
	adminCred s3api.ConsoleCredential
	identity  *s3api.Identity // Cached admin identity after authentication
}

// NewConsoleHandlers creates a new console handlers instance
func NewConsoleHandlers(s3Ops *s3api.S3Operations, adminCred s3api.ConsoleCredential) *ConsoleHandlers {
	return &ConsoleHandlers{
		s3Ops:     s3Ops,
		adminCred: adminCred,
	}
}

// SetupRoutes configures all the routes for the console
func (h *ConsoleHandlers) SetupRoutes(r *gin.Engine) {
	// Setup session middleware
	store := cookie.NewStore([]byte("seaweedfs-s3-console-secret-key-change-in-production"))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})
	r.Use(sessions.Sessions("seaweedfs-console", store))

	// Public routes (no authentication required)
	ui := r.Group("/ui")
	ui.GET("/login", h.handleLogin)
	ui.POST("/login", h.handleLoginPost)
	ui.POST("/logout", h.handleLogout)

	// Protected routes (authentication required)
	protected := ui.Group("")
	protected.Use(h.requireAuthentication())
	{
		// Main pages
		protected.GET("", h.handleOverview)
		protected.GET("/", h.handleOverview)
		protected.GET("/buckets", h.handleBuckets)
		protected.GET("/buckets/:bucketName", h.handleBucketBrowser)
		protected.GET("/settings", h.handleSettings)
		protected.GET("/api-status", h.handleAPIStatus)

		// API endpoints
		api := protected.Group("/api")
		{
			// Bucket management
			api.GET("/buckets", h.handleListBucketsAPI)
			api.POST("/buckets", h.handleCreateBucketAPI)
			api.DELETE("/buckets/:bucketName", h.handleDeleteBucketAPI)

			// Bucket browsing and file operations
			api.GET("/buckets/:bucketName/browse", h.handleBrowseBucketAPI)
			api.POST("/buckets/:bucketName/folders", h.handleCreateFolderAPI)
			api.POST("/buckets/:bucketName/upload", h.handleUploadAPI)
			api.DELETE("/buckets/:bucketName/delete", h.handleDeleteObjectAPI)
			api.GET("/buckets/:bucketName/download", h.handleDownloadAPI)

			// System
			api.GET("/test-connection", h.handleTestConnectionAPI)
		}
	}
}

// requireAuthentication middleware ensures the user is logged in
func (h *ConsoleHandlers) requireAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		authenticated := session.Get("authenticated")

		if authenticated != true {
			// For HTMX requests, return 401 so frontend can handle redirect
			if c.GetHeader("HX-Request") == "true" {
				c.Header("HX-Redirect", "/ui/login")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
				c.Abort()
				return
			}
			// For regular requests, redirect to login
			c.Redirect(http.StatusFound, "/ui/login")
			c.Abort()
			return
		}

		// Get cached identity from session or authenticate
		if h.identity == nil {
			identity, err := h.s3Ops.AuthenticateConsole(h.adminCred.AccessKey, h.adminCred.SecretKey)
			if err != nil {
				// Clear session and redirect to login
				session.Clear()
				session.Save()
				c.Redirect(http.StatusFound, "/ui/login")
				c.Abort()
				return
			}
			h.identity = identity
		}

		// Store identity in context for handlers
		c.Set("console_identity", h.identity)
		c.Next()
	}
}

// handleLogin renders the login page
func (h *ConsoleHandlers) handleLogin(c *gin.Context) {
	// If already authenticated, redirect to overview
	session := sessions.Default(c)
	if session.Get("authenticated") == true {
		c.Redirect(http.StatusFound, "/ui/")
		return
	}

	errorMessage := c.Query("error")
	c.Header("Content-Type", "text/html")
	component := app.Login(errorMessage)
	component.Render(c.Request.Context(), c.Writer)
}

// handleLoginPost processes login form submission
func (h *ConsoleHandlers) handleLoginPost(c *gin.Context) {
	accessKey := c.PostForm("accessKey")
	secretKey := c.PostForm("secretKey")

	// Validate credentials
	if accessKey != h.adminCred.AccessKey || secretKey != h.adminCred.SecretKey {
		c.Redirect(http.StatusFound, "/ui/login?error=Invalid+credentials")
		return
	}

	// Set session
	session := sessions.Default(c)
	session.Set("authenticated", true)
	session.Set("access_key", accessKey)
	if err := session.Save(); err != nil {
		c.Redirect(http.StatusFound, "/ui/login?error=Session+error")
		return
	}

	// Redirect to overview
	c.Redirect(http.StatusFound, "/ui/")
}

// handleLogout clears the session and redirects to login
func (h *ConsoleHandlers) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	// Clear cached identity
	h.identity = nil

	c.Redirect(http.StatusFound, "/ui/login")
}

// handleOverview renders the overview page
func (h *ConsoleHandlers) handleOverview(c *gin.Context) {
	bucketsData, err := h.getBucketsData(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/html")
	component := layout.Layout(c, app.Overview(bucketsData))
	component.Render(c.Request.Context(), c.Writer)
}

// handleBuckets renders the buckets listing page
func (h *ConsoleHandlers) handleBuckets(c *gin.Context) {
	bucketsData, err := h.getBucketsData(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/html")
	component := layout.Layout(c, app.Buckets(bucketsData))
	component.Render(c.Request.Context(), c.Writer)
}

// handleBucketBrowser renders the bucket browser page
func (h *ConsoleHandlers) handleBucketBrowser(c *gin.Context) {
	bucketName := c.Param("bucketName")
	currentPath := c.Query("path")

	browserData, err := h.getBucketBrowserData(c, bucketName, currentPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/html")

	if c.GetHeader("HX-Request") == "true" {
		component := app.BucketBrowserCard(browserData)
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	component := layout.Layout(c, app.BucketBrowser(browserData))
	component.Render(c.Request.Context(), c.Writer)
}

// handleSettings renders the settings page (placeholder)
func (h *ConsoleHandlers) handleSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Settings page will be implemented",
	})
}

// handleAPIStatus renders the API status page
func (h *ConsoleHandlers) handleAPIStatus(c *gin.Context) {
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	err := h.s3Ops.TestConnection(ctx)
	connected := err == nil

	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"s3_connected": connected,
		"identity":     identity.Name,
	})
}

// API Handlers

// handleListBucketsAPI returns buckets data as JSON
func (h *ConsoleHandlers) handleListBucketsAPI(c *gin.Context) {
	bucketsData, err := h.getBucketsData(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, bucketsData)
}

// handleCreateBucketAPI creates a new bucket
func (h *ConsoleHandlers) handleCreateBucketAPI(c *gin.Context) {
	var req data.CreateBucketRequest

	// Handle both JSON and form data
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Region == "" {
			req.Region = "us-east-1"
		}
	}

	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	if err := h.s3Ops.CreateBucket(ctx, identity, req.Name, req.Region); err != nil {
		// For HTMX requests, we need to return JSON error so HTMX can handle it
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For HTMX requests, return updated buckets HTML
	if c.GetHeader("HX-Request") == "true" {
		bucketsData, err := h.getBucketsData(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		component := app.BucketsContainer(bucketsData)
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Bucket created successfully"})
}

// handleDeleteBucketAPI deletes a bucket
func (h *ConsoleHandlers) handleDeleteBucketAPI(c *gin.Context) {
	bucketName := c.Param("bucketName")
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	if err := h.s3Ops.DeleteBucket(ctx, identity, bucketName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For HTMX requests, return updated buckets HTML
	if c.GetHeader("HX-Request") == "true" {
		bucketsData, err := h.getBucketsData(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		component := app.BucketsContainer(bucketsData)
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Bucket deleted successfully"})
}

// handleTestConnectionAPI tests the S3 connection
func (h *ConsoleHandlers) handleTestConnectionAPI(c *gin.Context) {
	ctx := c.Request.Context()
	err := h.s3Ops.TestConnection(ctx)
	connected := err == nil

	c.JSON(http.StatusOK, gin.H{
		"connected": connected,
		"timestamp": time.Now(),
	})
}

// getBucketsData fetches bucket data for the UI
func (h *ConsoleHandlers) getBucketsData(c *gin.Context) (data.BucketsData, error) {
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	buckets, err := h.s3Ops.ListBuckets(ctx, identity)
	if err != nil {
		return data.BucketsData{}, err
	}

	var totalObjects int64
	var totalSize int64

	for _, bucket := range buckets {
		totalObjects += bucket.ObjectCount
		totalSize += bucket.Size
	}

	// Test connection
	connected := h.s3Ops.TestConnection(ctx) == nil

	return data.BucketsData{
		Buckets:        buckets,
		TotalObjects:   totalObjects,
		TotalSize:      totalSize,
		S3ApiConnected: connected,
		LastUpdated:    time.Now(),
	}, nil
}

// getBucketBrowserData fetches data for the bucket browser
func (h *ConsoleHandlers) getBucketBrowserData(c *gin.Context, bucketName, currentPath string) (data.BucketBrowserData, error) {
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	items, err := h.s3Ops.ListBucketContents(ctx, identity, bucketName, currentPath)
	if err != nil {
		return data.BucketBrowserData{}, err
	}

	return data.BucketBrowserData{
		BucketName:  bucketName,
		CurrentPath: currentPath,
		Items:       items,
	}, nil
}

// handleBrowseBucketAPI returns bucket contents as JSON
func (h *ConsoleHandlers) handleBrowseBucketAPI(c *gin.Context) {
	bucketName := c.Param("bucketName")
	currentPath := c.Query("path")

	browserData, err := h.getBucketBrowserData(c, bucketName, currentPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, browserData)
}

// handleCreateFolderAPI creates a new folder in the bucket
func (h *ConsoleHandlers) handleCreateFolderAPI(c *gin.Context) {
	bucketName := c.Param("bucketName")
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	var req data.CreateFolderRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create folder (empty object with trailing slash)
	folderPath := filepath.Join(req.CurrentPath, req.FolderName) + "/"
	if err := h.s3Ops.CreateFolder(ctx, identity, bucketName, folderPath); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Redirect back to bucket browser
	redirectPath := fmt.Sprintf("/ui/buckets/%s", bucketName)
	if req.CurrentPath != "" {
		redirectPath += "?path=" + req.CurrentPath
	}
	c.Header("HX-Redirect", redirectPath)
	c.Status(http.StatusOK)
}

// handleUploadAPI handles file uploads to the bucket
func (h *ConsoleHandlers) handleUploadAPI(c *gin.Context) {
	bucketName := c.Param("bucketName")
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	// Remove memory limit for multipart parsing to support unlimited file sizes
	c.Request.ParseMultipartForm(0) // No limit

	currentPath := c.PostForm("currentPath")

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse multipart form: " + err.Error()})
		return
	}

	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No files provided"})
		return
	}

	uploadedCount := 0
	var uploadErrors []string

	for _, fileHeader := range files {
		if err := h.uploadSingleFile(ctx, identity, bucketName, currentPath, fileHeader); err != nil {
			uploadErrors = append(uploadErrors, fmt.Sprintf("%s: %v", fileHeader.Filename, err))
			continue
		}
		uploadedCount++
	}

	if len(uploadErrors) > 0 && uploadedCount == 0 {
		// All uploads failed
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("All uploads failed: %s", strings.Join(uploadErrors, "; "))})
		return
	} else if len(uploadErrors) > 0 {
		// Some uploads failed
		c.JSON(http.StatusPartialContent, gin.H{
			"message": fmt.Sprintf("Uploaded %d files with %d errors", uploadedCount, len(uploadErrors)),
			"count":   uploadedCount,
			"errors":  uploadErrors,
		})
		return
	}

	if c.GetHeader("HX-Request") == "true" {
		browserData, err := h.getBucketBrowserData(c, bucketName, currentPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Header("Content-Type", "text/html")
		component := app.BucketBrowserCard(browserData)
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Successfully uploaded %d files", uploadedCount),
		"count":   uploadedCount,
	})
}

// uploadSingleFile uploads a single file to the bucket using streaming
func (h *ConsoleHandlers) uploadSingleFile(ctx context.Context, identity *s3api.Identity, bucketName, currentPath string, fileHeader *multipart.FileHeader) error {
	file, err := fileHeader.Open()
	if err != nil {
		return err
	}
	defer file.Close()

	// Determine the object key
	objectKey := fileHeader.Filename
	if currentPath != "" {
		objectKey = filepath.Join(currentPath, fileHeader.Filename)
	}

	// Get content type
	contentType := fileHeader.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Use streaming upload to support unlimited file sizes
	return h.s3Ops.PutObjectStream(ctx, identity, bucketName, objectKey, file, fileHeader.Size, contentType)
}

// handleDeleteObjectAPI deletes a file or folder from the bucket
func (h *ConsoleHandlers) handleDeleteObjectAPI(c *gin.Context) {
	bucketName := c.Param("bucketName")
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	var req data.DeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.IsDirectory {
		// Delete folder and all its contents
		if err := h.s3Ops.DeleteFolder(ctx, identity, bucketName, req.Path); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Delete single file
		if err := h.s3Ops.DeleteObject(ctx, identity, bucketName, req.Path); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Deleted successfully"})
}

// handleDownloadAPI handles file downloads from the bucket
func (h *ConsoleHandlers) handleDownloadAPI(c *gin.Context) {
	bucketName := c.Param("bucketName")
	objectPath := c.Query("path")
	identity := c.MustGet("console_identity").(*s3api.Identity)
	ctx := c.Request.Context()

	if objectPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path parameter is required"})
		return
	}

	// Get object
	content, contentType, err := h.s3Ops.GetObject(ctx, identity, bucketName, objectPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Set headers for download
	fileName := filepath.Base(objectPath)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	c.Header("Content-Type", contentType)
	c.Data(http.StatusOK, contentType, content)
}

package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/netdoctor/netdoctor/internal/doctor"
)

//go:embed static/dist/*
var staticDist embed.FS

type Server struct {
	service *doctor.Service
	handler http.Handler
}

func New(service *doctor.Service) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	server := &Server{service: service, handler: router}
	router.GET("/api/snapshot", server.snapshot)
	router.GET("/api/events", server.events)
	router.GET("/api/processes", server.processes)
	router.GET("/api/interfaces", server.interfaces)
	server.mountUI(router)
	return server
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) snapshot(c *gin.Context) {
	snapshot := s.service.Snapshot()
	snapshot.Events = nil
	snapshot.Interfaces = nil
	c.JSON(http.StatusOK, snapshot)
}

func (s *Server) events(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().Events)
}

func (s *Server) processes(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().ProcessTraffic)
}

func (s *Server) interfaces(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().SystemTCP)
}

func (s *Server) mountUI(router *gin.Engine) {
	dist, err := fs.Sub(staticDist, "static/dist")
	if err != nil {
		router.NoRoute(func(c *gin.Context) {
			c.String(http.StatusInternalServerError, "web UI is not embedded")
		})
		return
	}
	files := http.FileServer(http.FS(dist))
	router.NoRoute(func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(dist, path); err != nil {
			path = "index.html"
		}
		c.Request.URL.Path = "/" + path
		files.ServeHTTP(c.Writer, c.Request)
	})
}

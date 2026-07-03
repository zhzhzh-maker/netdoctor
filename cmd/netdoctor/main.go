package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/netdoctor/netdoctor/internal/doctor"
	"github.com/netdoctor/netdoctor/internal/output"
	"github.com/netdoctor/netdoctor/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("missing command")
	}

	switch os.Args[1] {
	case "probe":
		return probe(os.Args[2:])
	case "run":
		return runCollector(os.Args[2:])
	case "serve":
		return serve(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func probe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	objectPath := fs.String("object", "", "optional compiled eBPF object path")
	eventLimit := fs.Int("event-limit", 2048, "number of recent eBPF events kept in memory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := doctor.New(doctor.Options{ObjectPath: *objectPath, EventLimit: *eventLimit})
	if err := service.Start(ctx); err != nil {
		return output.JSON(os.Stdout, service.Snapshot())
	}
	defer service.Close()
	return output.JSON(os.Stdout, service.Snapshot())
}

func runCollector(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	objectPath := fs.String("object", "", "compiled eBPF object path")
	eventLimit := fs.Int("event-limit", 2048, "number of recent eBPF events kept in memory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*objectPath) == "" {
		return errors.New("run requires -object")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := doctor.New(doctor.Options{ObjectPath: *objectPath, EventLimit: *eventLimit})
	if err := service.Start(ctx); err != nil {
		return err
	}
	defer service.Close()

	<-ctx.Done()
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "HTTP listen address")
	objectPath := fs.String("object", "", "optional compiled eBPF object path")
	eventLimit := fs.Int("event-limit", 4096, "number of recent eBPF events kept in memory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := doctor.New(doctor.Options{ObjectPath: *objectPath, EventLimit: *eventLimit})
	if err := service.Start(ctx); err != nil {
		return err
	}
	defer service.Close()

	server := &http.Server{
		Addr:    *addr,
		Handler: web.New(service).Handler(),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("netdoctor web listening on http://%s", *addr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5_000_000_000)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `netdoctor

Usage:
  netdoctor probe [-object netdoctor_bpfel.o]
  netdoctor run -object netdoctor_bpfel.o
  netdoctor serve [-addr 127.0.0.1:8080] [-object netdoctor_bpfel.o]

Commands:
  probe   check cilium/ebpf availability and optionally attach an object once
  run     attach an eBPF object and keep collectors running
  serve   start the optional web UI and JSON API`)
}

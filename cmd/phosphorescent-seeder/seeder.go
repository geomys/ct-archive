// Command phosphorescent-seeder is a stateless, memory-safe BitTorrent seeder
// for a single existing torrent file, from read-only, known-good data.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	"golang.org/x/time/rate"
)

func main() {
	torrentFile := flag.String("torrent", "", "path to torrent file")
	dataDir := flag.String("data", ".", "path to directory with data files")
	publicIP := flag.String("ip", "", "public IP address to announce to peers (optional)")
	uploadLimit := flag.Float64("upload-limit", 0, "upload bandwidth limit in Mbps (0 = unlimited)")
	flag.Parse()

	if *torrentFile == "" || *dataDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	mi, err := metainfo.LoadFromFile(*torrentFile)
	if err != nil {
		log.Fatalf("failed to load torrent file: %v", err)
	}

	info, err := mi.UnmarshalInfo()
	if err != nil {
		log.Fatalf("failed to unmarshal info: %v", err)
	}

	// Check that data directory contains all files in the torrent, and that
	// they have the right size.
	for _, file := range info.Files {
		filePath := filepath.Join(*dataDir, filepath.Join(file.Path...))
		stat, err := os.Stat(filePath)
		if err != nil {
			log.Fatalf("data file missing: %s", filePath)
		}
		if file.Length != 0 && stat.Size() != file.Length {
			log.Fatalf("data file size mismatch for %s: expected %d, got %d",
				filePath, file.Length, stat.Size())
		}
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.Seed = true
	cfg.NoDefaultPortForwarding = true

	if *publicIP != "" {
		ip := net.ParseIP(*publicIP)
		if ip == nil {
			log.Fatalf("invalid IP address: %s", *publicIP)
		}
		if ip4 := ip.To4(); ip4 != nil {
			cfg.PublicIp4 = ip4
		} else {
			cfg.PublicIp6 = ip
		}
	}

	if *uploadLimit > 0 {
		// Convert megabits per second to bytes per second
		bytesPerSecond := (*uploadLimit * 1_000_000) / 8
		cfg.UploadRateLimiter = rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond))
	}

	cl, err := torrent.NewClient(cfg)
	if err != nil {
		log.Fatalf("failed to create torrent client: %v", err)
	}
	defer cl.Close()

	t, err := cl.AddTorrent(mi)
	if err != nil {
		log.Fatalf("failed to add torrent: %v", err)
	}

	// Set up storage pointing to the data directory with no piece verification
	t.Drop()
	t, _ = cl.AddTorrentOpt(torrent.AddTorrentOpts{
		InfoHash:                 mi.HashInfoBytes(),
		DisableInitialPieceCheck: true,
		Storage: storage.NewFileOpts(storage.NewFileClientOpts{
			ClientBaseDir: *dataDir,
			FilePathMaker: func(opts storage.FilePathMakerOpts) string {
				return filepath.Join(opts.File.Path...)
			},
			PieceCompletion: allComplete{},
		}),
	})

	err = t.MergeSpec(&torrent.TorrentSpec{
		AddTorrentOpts: torrent.AddTorrentOpts{
			InfoBytes: mi.InfoBytes,
		},
		Trackers: mi.UpvertedAnnounceList(),
	})
	if err != nil {
		log.Fatalf("failed to merge spec: %v", err)
	}

	log.Printf("seeding: %s", t.Name())
	log.Printf("info hash: %s", t.InfoHash().HexString())
	log.Printf("listening on: %v", cl.ListenAddrs())

	// Print stats every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			stats := t.Stats()
			log.Printf("peers: %d active, %d total | uploaded: %s | downloaded: %s",
				stats.ActivePeers, stats.TotalPeers,
				formatBytes(stats.BytesWrittenData.Int64()),
				formatBytes(stats.BytesReadData.Int64()))
		case <-sigCh:
			log.Println("shutting down...")
			return
		}
	}
}

// allComplete is a PieceCompletion that reports all pieces as complete.
// Used for seeding read-only data without verification.
type allComplete struct{}

func (allComplete) Get(metainfo.PieceKey) (storage.Completion, error) {
	return storage.Completion{Complete: true, Ok: true}, nil
}

func (allComplete) Set(metainfo.PieceKey, bool) error {
	return nil
}

func (allComplete) Close() error {
	return nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

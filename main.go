package main

import (
	"context"
	"flag"
	"os"
	"time"

	image2 "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

func main() {
	imageFlag := flag.String("image", "", "image name")
	remoteFlag := flag.String("remote", "", "server url")
	outputTypeFlag := flag.String("output", "table", "output type such as table, json.")
	flag.Parse()

	if err := log.InitLogger(true, false); err != nil {
		log.Logger.Fatalf("error happened: %v", xerrors.Errorf("failed to initialize a logger: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	defer cancel()

	localCache, err := cache.NewFSCache("/Users/batuhan.apaydin/Library/Caches/trivy")
	if err != nil {
		log.Logger.Fatalf("could not initialize f: %v", err)
	}

	sc, cleanUp, err := initializeDockerScanner(ctx, *imageFlag, localCache, client.CustomHeaders{}, client.RemoteURL(*remoteFlag), time.Second*5000)
	if err != nil {
		log.Logger.Fatalf("could not initialize scanner: %v", err)
	}

	defer cleanUp()

	results, err := sc.ScanArtifact(ctx, types.ScanOptions{
		VulnType:            []string{"os", "library"},
		ScanRemovedPackages: true,
		ListAllPackages:     true,
	})

	log.Logger.Infof("%d vulnerability/ies found", len(results[0].Vulnerabilities))

	if err = report.WriteResults(*outputTypeFlag, os.Stdout, []dbTypes.Severity{dbTypes.SeverityUnknown}, results, "", false); err != nil {
		log.Logger.Fatalf("could not write results: %v", xerrors.Errorf("unable to write results: %w", err))
	}
}

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, customHeaders client.CustomHeaders, url client.RemoteURL, timeout time.Duration) (scanner.Scanner, func(), error) {
	scannerScanner := client.NewProtobufClient(url)
	clientScanner := client.NewScanner(customHeaders, scannerScanner)
	dockerOption, err := types.GetDockerOption(timeout)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	imageImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	artifact := image2.NewArtifact(imageImage, artifactCache)
	scanner2 := scanner.NewScanner(clientScanner, artifact)
	return scanner2, func() {
		cleanup()
	}, nil
}

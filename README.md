![trivy_logo](./trivy_logo.png)

# Description

Trivy (tri pronounced like trigger, vy pronounced like envy) is a simple and comprehensive vulnerability scanner for containers and other artifacts. A software vulnerability is a glitch, flaw, or weakness present in the software or in an Operating System. Trivy detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.). Trivy is easy to use. Just install the binary and you're ready to scan. All you need to do for scanning is to specify a target such as an image name of the container.
> Credit: https://github.com/aquasecurity/trivy

# Prerequisites

* Go 1.15.7
* Trivy 0.17.2

# Getting Started

In this hands-on guide, we are going to develop a Trivy client with the Go code. Trivy has client/server mode. Trivy server has vulnerability database and Trivy client doesn't have to download vulnerability database. It is useful if you want to scan images at multiple locations and do not want to download the database at every location.

In order to do that, we need to start Trivy server first using the following command:
```bash
$ trivy server --cache-dir ./trivycache
2021-02-07T14:13:52.210+0300    INFO    Need to update DB
2021-02-07T14:13:52.211+0300    INFO    Downloading DB...
2021-02-07T14:13:59.275+0300    INFO    Listening localhost:4954...
```

Lets move on with client code.
```golang
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
	outputTypeFlag := flag.String("output", "", "output type such as table, json.")
	flag.Parse()

	if err := log.InitLogger(true, false); err != nil {
		log.Logger.Fatalf("error happened: %v", xerrors.Errorf("failed to initialize a logger: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	defer cancel()

	localCache, err := cache.NewFSCache(os.Getenv("HOME") + "/Library/Caches/trivy")
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
	if err != nil {
		log.Logger.Fatalf("could not scan image: %v", err)
	}

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
```

Lets try it with running the code
```bash
$ go run ./main.go --image alpine:3.10 --remote http://localhost:4954
2021-02-07T14:17:25.718+0300    DEBUG   Artifact ID: sha256:be4e4bea2c2e15b403bb321562e78ea84b501fb41497472e91ecb41504e8a27c
2021-02-07T14:17:25.718+0300    DEBUG   Blob IDs: [sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3]
2021-02-07T14:17:25.725+0300    INFO    4 vulnerability/ies found

alpine:3.10 (alpine 3.10.5)
===========================
Total: 4 (UNKNOWN: 0)

+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| musl         | CVE-2020-28928   | MEDIUM   | 1.1.22-r3         | 1.1.22-r4     | In musl libc through 1.2.1,           |
|              |                  |          |                   |               | wcsnrtombs mishandles particular      |
|              |                  |          |                   |               | combinations of destination buffer... |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-28928 |
+--------------+------------------+          +-------------------+---------------+---------------------------------------+
| libcrypto1.1 | CVE-2020-1971    |          | 1.1.1g-r0         | 1.1.1i-r0     | openssl: EDIPARTYNAME                 |
|              |                  |          |                   |               | NULL pointer de-reference             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1971  |
+--------------+                  +          +                   +               +                                       +
| libssl1.1    |                  |          |                   |               |                                       |
|              |                  |          |                   |               |                                       |
|              |                  |          |                   |               |                                       |
+--------------+------------------+          +-------------------+---------------+---------------------------------------+
| musl-utils   | CVE-2020-28928   |          | 1.1.22-r3         | 1.1.22-r4     | In musl libc through 1.2.1,           |
|              |                  |          |                   |               | wcsnrtombs mishandles particular      |
|              |                  |          |                   |               | combinations of destination buffer... |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-28928 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
```

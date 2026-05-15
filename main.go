package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Ephemeral-Dust/pia-wg-config/pia"
	cli "github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:   "pia-wg-config",
		Usage:  "generate a wireguard config for private internet access",
		Action: defaultAction,

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "outfile",
				Aliases: []string{"o"},
				Usage:   "The file to write the wireguard config to",
			},
			&cli.StringFlag{
				Name:    "region",
				Aliases: []string{"r"},
				Value:   "ca_toronto",
				Usage:   "The private internet access region to connect to",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Value:   false,
				Usage:   "Print verbose output",
			},
			&cli.BoolFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Value:   false,
				Usage:   "Add Server common name to the config",
			},
			&cli.BoolFlag{
				Name:    "port-forwarding",
				Aliases: []string{"p"},
				Value:   false,
				Usage:   "Only get servers with port forwarding enabled",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Value:   false,
				Usage:   "Print machine-readable metadata as JSON to stdout",
			},
			&cli.StringFlag{
				Name:  "metadata-file",
				Usage: "Write machine-readable metadata as JSON to this file",
			},
			&cli.StringFlag{
				Name:  "serverlist-cache",
				Usage: "Path to server-list cache file",
			},
			&cli.StringFlag{
				Name:  "serverlist-cache-ttl",
				Value: "24h",
				Usage: "Max age to use cache without refresh (e.g. 24h, 30m)",
			},
			&cli.StringFlag{
				Name:  "serverlist-cache-max-age",
				Value: "168h",
				Usage: "Max age before cache is treated as invalid (e.g. 168h)",
			},
			&cli.BoolFlag{
				Name:  "serverlist-force-refresh",
				Value: false,
				Usage: "Force fresh server-list fetch even if cache is fresh",
			},
			&cli.IntFlag{
				Name:  "serverlist-fetch-retries",
				Value: 5,
				Usage: "Max server-list fetch attempts",
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func defaultAction(c *cli.Context) error {
	username := c.Args().Get(0)
	password := c.Args().Get(1)
	verbose := c.Bool("verbose")
	serverName := c.Bool("server")
	portForwarding := c.Bool("port-forwarding")
	region := c.String("region")
	outfile := c.String("outfile")
	printJSON := c.Bool("json")
	metadataFile := c.String("metadata-file")

	cacheTTL, err := time.ParseDuration(c.String("serverlist-cache-ttl"))
	if err != nil {
		return fmt.Errorf("invalid --serverlist-cache-ttl: %w", err)
	}
	cacheMaxAge, err := time.ParseDuration(c.String("serverlist-cache-max-age"))
	if err != nil {
		return fmt.Errorf("invalid --serverlist-cache-max-age: %w", err)
	}
	serverListOpts := pia.ServerListOptions{
		CachePath:    c.String("serverlist-cache"),
		CacheTTL:     cacheTTL,
		CacheMaxAge:  cacheMaxAge,
		ForceRefresh: c.Bool("serverlist-force-refresh"),
		FetchRetries: c.Int("serverlist-fetch-retries"),
	}

	if verbose {
		log.Print("Creating PIA client")
	}
	piaClient, err := pia.NewPIAClient(username, password, region, verbose, portForwarding, serverListOpts)
	if err != nil {
		return err
	}

	if verbose {
		log.Print("creating wg config generator")
	}
	wgConfigGenerator := pia.NewPIAWgGenerator(piaClient, pia.PIAWgGeneratorConfig{
		Verbose:        verbose,
		ServerName:     serverName,
		Region:         region,
		PortForwarding: portForwarding,
	})

	if verbose {
		log.Print("Generating wireguard config")
	}
	config, metadata, err := wgConfigGenerator.Generate()
	if err != nil {
		return err
	}

	// Set config path on metadata now that we know the outfile.
	metadata.WireguardConfig = outfile

	// Write wireguard config.
	if outfile != "" {
		if err := os.WriteFile(outfile, []byte(config), 0644); err != nil {
			return err
		}
	} else if !printJSON {
		// Only print config to stdout when --json is not active.
		log.Println(config)
	}

	// Marshal metadata once for reuse.
	var metadataBytes []byte
	if printJSON || metadataFile != "" {
		metadataBytes, err = json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return err
		}
	}

	if printJSON {
		if _, err := fmt.Fprintln(os.Stdout, string(metadataBytes)); err != nil {
			return err
		}
	}

	if metadataFile != "" {
		if err := os.WriteFile(metadataFile, metadataBytes, 0644); err != nil {
			return err
		}
	}

	return nil
}

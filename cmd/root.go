/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ory/hydra/driver/configuration"

	conf "github.com/coupa/foundation-go/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ory/viper"

	"github.com/ory/hydra/cmd/cli"
	"github.com/ory/hydra/x"
)

var cfgFile string

var (
	Version = "master"
	Date    = "undefined"
	Commit  = "undefined"
)

// This represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "hydra",
	Short: "Run and manage ORY Hydra",
}

var cmdHandler = cli.NewHandler()

// Execute adds all child commands to the root command sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default is $HOME/.hydra.yaml)")
	RootCmd.PersistentFlags().Bool("skip-tls-verify", false, "Foolishly accept TLS certificates signed by unkown certificate authorities")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	smName := os.Getenv("AWSSM_NAME")
	if smName != "" {
		if os.Getenv("AWS_REGION") == "" {
			//Default region to us-east-1
			if err := os.Setenv("AWS_REGION", "us-east-1"); err != nil {
				log.Fatalf("Error setting AWS_REGION: %v", err)
			}
		}
		if err := conf.WriteSecretsToENV(smName); err != nil {
			log.Fatalf("Error reading from Secrets Manager: %v", err)
		}
		if err := retrieveDBCerts(); err != nil {
			log.Fatal(err)
		}
	}

	if cfgFile != "" {
		// enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		path := absPathify("$HOME")
		if _, err := os.Stat(filepath.Join(path, ".hydra.yml")); err != nil {
			_, _ = os.Create(filepath.Join(path, ".hydra.yml"))
		}

		viper.SetConfigType("yaml")
		viper.SetConfigName(".hydra") // name of config file (without extension)
		viper.AddConfigPath("$HOME")  // adding home directory as first search path
	}

	viper.SetDefault(configuration.ViperKeyLogLevel, "info")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf(`Config file not found because "%s"`, err)
		fmt.Println("")
	}
}

func absPathify(inPath string) string {
	if strings.HasPrefix(inPath, "$HOME") {
		inPath = userHomeDir() + inPath[5:]
	}

	if strings.HasPrefix(inPath, "$") {
		end := strings.Index(inPath, string(os.PathSeparator))
		inPath = os.Getenv(inPath[1:end]) + inPath[end:]
	}

	if filepath.IsAbs(inPath) {
		return filepath.Clean(inPath)
	}

	p, err := filepath.Abs(inPath)
	if err == nil {
		return filepath.Clean(p)
	}
	return ""
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func retrieveDBCerts() error {
	rdscertsSecretName := os.Getenv("AWS_RDS_CERTS_SECRET_NAME")
	if rdscertsSecretName == "" {
		return nil
	}
	secrets, _, err := conf.GetSecrets(rdscertsSecretName)
	if err != nil {
		return fmt.Errorf("Error getting rds certs from Secrets Manager: %v", err)
	}
	pem := secrets[x.RdsSSLCert]
	if pem == "" {
		return fmt.Errorf("RDS certificate (%s) on Secrets Manager (%s) not found", x.RdsSSLCert, rdscertsSecretName)
	}
	pem = x.FixPemFormat(pem)
	viper.Set(configuration.ViperKeyDBSSLCert, pem)
	log.Info("Successfully set RDS cert from Secrets Manager")
	return nil
}
